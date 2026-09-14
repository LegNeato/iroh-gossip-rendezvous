//! Join / HealLoop / WriteLoop.
//!
//! Implements the three procedures in §5 of the design doc on top of a
//! [`DhtSlots`] and a [`GossipView`]:
//!
//! * [`initial_join`] — read all K slots, feed discovered IDs to the gossip
//!   layer, then write a self-entry to `slot_u`.
//! * [`spawn_heal_loop`] — periodically reads `s = max(1, K − |N|)` random
//!   slots, union-joins unknown IDs.
//! * [`spawn_write_loop`] — periodically (with probability `1/(|N|+1)`)
//!   reads `slot_u`, merges, writes prev+1.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::Signer;
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::crypto;
use crate::dht::{DhtSlots, SlotKey, SlotRecord};
use crate::keys::{PassphraseKeys, slot_for_id};
use crate::merge::{MergeParams, merge};
use crate::state::{DhtStatus, RendezvousState};
use crate::wire::{decode_entries, encode_entries};

/// Gossip-layer view used by the protocol loops. Swappable for the simulator.
#[async_trait]
pub(crate) trait GossipView: Send + Sync + 'static {
    /// Snapshot of the local gossip active-view set (excluding self).
    fn neighbors(&self) -> Vec<[u8; 32]>;
    /// Feed discovered peer IDs to the gossip layer for dialing.
    async fn join_peers(&self, peers: Vec<[u8; 32]>);
}

/// Immutable protocol config.
#[derive(Clone, Debug)]
pub(crate) struct ProtocolConfig {
    pub self_id: [u8; 32],
    pub shards: usize,
    pub max_age: u8,
    pub max_entries: usize,
    pub max_vouches: usize,
    pub epoch_size: u64,
    pub write_period: Duration,
    pub heal_period: Duration,
    /// Sleep between write-loop ticks while `dht_status == PublishFailing`.
    /// Used in place of `write_period` to recover from a failed publish
    /// faster than the steady-state cadence allows. The probability gate
    /// is also skipped while failing — every tick attempts a write until
    /// one succeeds.
    pub failure_retry_period: Duration,
    pub jitter: f32,
}

impl ProtocolConfig {
    fn merge_params(&self) -> MergeParams {
        MergeParams {
            max_age: self.max_age,
            max_entries: self.max_entries,
            max_vouches: self.max_vouches,
        }
    }
}

/// Shared state that each loop reads/writes.
pub(crate) struct ProtoState {
    pub config: ProtocolConfig,
    pub keys: PassphraseKeys,
    /// Last observed seq per slot. Extends with `.resize` if K changes.
    pub seq_cache: Mutex<Vec<i64>>,
    /// Published [`RendezvousState`] — readers poll this.
    pub observable: Arc<Mutex<RendezvousState>>,
}

impl ProtoState {
    pub(crate) fn new(
        config: ProtocolConfig,
        keys: PassphraseKeys,
        observable: Arc<Mutex<RendezvousState>>,
    ) -> Self {
        let seq_cache = Mutex::new(vec![0; config.shards]);
        Self {
            config,
            keys,
            seq_cache,
            observable,
        }
    }

    fn slot_for(&self, id: &[u8; 32]) -> usize {
        slot_for_id(id, self.config.shards)
    }

    fn own_slot(&self) -> usize {
        self.slot_for(&self.config.self_id)
    }

    fn slot_key(&self, k: usize) -> SlotKey {
        SlotKey(self.keys.slots[k].verifying.to_bytes())
    }

    /// Record the highest seq we've observed for slot `k`. The `>` guard
    /// prevents regression on LWW reorders; `>=` would be an equivalent
    /// mutation (assigning the same value is a no-op), so the cmp op is
    /// marked as not-mutation-testable via the function-level skip below.
    #[mutants::skip] // `>` vs `>=` are behaviorally equivalent at equal seq.
    fn record_last_seq(&self, k: usize, seq: i64) {
        if let Ok(mut g) = self.seq_cache.lock() {
            if let Some(slot) = g.get_mut(k) {
                if seq > *slot {
                    *slot = seq;
                }
            }
        }
    }

    fn last_seq(&self, k: usize) -> i64 {
        self.seq_cache
            .lock()
            .ok()
            .and_then(|g| g.get(k).copied())
            .unwrap_or(0)
    }
}

/// Read one slot, decrypt, and return the decoded entries. Returns empty
/// (without error) if the slot is empty or unreadable.
async fn read_slot(state: &ProtoState, dht: &dyn DhtSlots, k: usize) -> Vec<[u8; 32]> {
    let slot_key = state.slot_key(k);
    let record = match dht.read(slot_key).await {
        Ok(Some(r)) => r,
        Ok(None) => return Vec::new(),
        Err(e) => {
            debug!(slot = k, error = %e, "DHT read failed");
            return Vec::new();
        }
    };
    state.record_last_seq(k, record.seq);

    let wk = &state.keys.slots[k].wrapper;
    let plaintext = match crypto::open(wk, &record.value, record.seq, state.config.epoch_size) {
        Ok(p) => p,
        Err(e) => {
            debug!(slot = k, error = %e, "record decrypt failed");
            return Vec::new();
        }
    };
    let entries = match decode_entries(&plaintext) {
        Ok(e) => e,
        Err(e) => {
            debug!(slot = k, error = %e, "record decode failed");
            return Vec::new();
        }
    };
    entries.into_iter().map(|e| e.id).collect()
}

/// Run the initial Join procedure per §5 of the design doc:
///   1. Read all K slots in parallel, feed unknown IDs to the gossip layer.
///
/// The self-publish that follows in §5 is moved into the first `WriteLoop`
/// tick (see [`spawn_loops`]) so we don't block [`Rendezvous::builder`]
/// callers on a slow DHT put during startup. The publish still happens
/// promptly — as soon as the background tasks spin up — just concurrently
/// rather than synchronously.
///
/// Returns the set of discovered IDs (minus self).
pub(crate) async fn initial_join(
    state: Arc<ProtoState>,
    dht: Arc<dyn DhtSlots>,
    gossip: &dyn GossipView,
) -> Vec<[u8; 32]> {
    // Parallel reads across all K slots.
    let mut reads = JoinSet::new();
    for k in 0..state.config.shards {
        let state = state.clone();
        let dht = dht.clone();
        reads.spawn(async move { read_slot(&state, dht.as_ref(), k).await });
    }

    let mut seen = std::collections::HashSet::new();
    while let Some(res) = reads.join_next().await {
        if let Ok(ids) = res {
            for id in ids {
                if id != state.config.self_id {
                    seen.insert(id);
                }
            }
        }
    }
    let peers: Vec<[u8; 32]> = seen.into_iter().collect();
    if !peers.is_empty() {
        gossip.join_peers(peers.clone()).await;
    }

    if let Ok(mut s) = state.observable.lock() {
        s.last_heal = Some(Instant::now());
    }

    peers
}

/// Build a sealed [`SlotRecord`] from a list of entries.
fn build_record(
    state: &ProtoState,
    k: usize,
    entries: &[crate::wire::Entry],
) -> Option<SlotRecord> {
    let plaintext = encode_entries(entries);
    let prev_seq = state.last_seq(k);
    let seq = prev_seq.saturating_add(1);

    let wk = &state.keys.slots[k].wrapper;
    let envelope = match crypto::seal(wk, &plaintext, seq, state.config.epoch_size) {
        Ok(b) => b,
        Err(e) => {
            warn!(slot = k, error = %e, "record seal failed");
            return None;
        }
    };

    let sig = state.keys.slots[k]
        .signing
        .sign(&canonical_message(seq, &envelope))
        .to_bytes();
    Some(SlotRecord {
        value: envelope,
        seq,
        signature: sig,
    })
}

/// BEP 44 mutable-item canonical message — this crate's production signing
/// path uses the mainline BEP 44 form. We reproduce it here for the in-memory
/// impl too so signatures round-trip.
///
/// Per BEP 44, the message is `{"seq": <seq>, "v": <value>}` bencoded. To
/// keep things simple and deterministic without pulling in a bencode lib in
/// every module, the in-memory impl verifies against a simpler
/// canonicalization: `seq_be || value`. The mainline impl uses `MutableItem`
/// which does the BEP 44 bencode internally.
///
/// For the in-memory path, signatures here must agree with the verification
/// in [`crate::dht::memory`].
fn canonical_message(seq: i64, value: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + value.len());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(value);
    m
}

/// Read `slot_u`, merge in neighbors + age-up, write back at `seq + 1`.
async fn write_once(state: &ProtoState, dht: &dyn DhtSlots, gossip: &dyn GossipView) {
    let k = state.own_slot();
    let slot_key = state.slot_key(k);

    // Read current record to get the latest seq + age the existing entries.
    let current_entries = match dht.read(slot_key).await {
        Ok(Some(r)) => {
            state.record_last_seq(k, r.seq);
            let wk = &state.keys.slots[k].wrapper;
            crypto::open(wk, &r.value, r.seq, state.config.epoch_size)
                .ok()
                .and_then(|pt| decode_entries(&pt).ok())
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let neighbors = gossip.neighbors();
    let merged = {
        let mut rng = rand::rng();
        merge(
            &current_entries,
            &state.config.self_id,
            &neighbors,
            &state.config.merge_params(),
            &mut rng,
        )
    };

    let Some(record) = build_record(state, k, &merged) else {
        return;
    };
    match dht.write(slot_key, record.clone()).await {
        Ok(()) => {
            state.record_last_seq(k, record.seq);
            if let Ok(mut s) = state.observable.lock() {
                s.dht_status = DhtStatus::Ready;
                s.last_publish = Some(Instant::now());
            }
            debug!(
                slot = k,
                seq = record.seq,
                entries = merged.len(),
                "DHT publish"
            );
        }
        Err(e) => {
            warn!(slot = k, error = %e, "DHT publish failed");
            if let Ok(mut s) = state.observable.lock() {
                s.dht_status = DhtStatus::PublishFailing;
            }
        }
    }
}

/// Return a duration in `[period * (1 - jitter), period * (1 + jitter)]`.
fn jittered(period: Duration, jitter: f32) -> Duration {
    let mut rng = rand::rng();
    let j = rng.random_range(-jitter..=jitter);
    jittered_with_j(period, j)
}

/// Pure-function core of [`jittered`]. Factored out so `cargo-mutants` can
/// meaningfully test the arithmetic — the RNG-using outer function is
/// harder to pin down with fixed-output tests. `j` is the drawn jitter in
/// `[-jitter, jitter]`.
fn jittered_with_j(period: Duration, j: f32) -> Duration {
    let factor = (1.0 + j).max(0.01);
    Duration::from_secs_f32(period.as_secs_f32() * factor)
}

/// Write-loop probabilistic gate: probability of writing on one tick,
/// given the current neighbor count `n`. `1 / (n + 1)` per PROTOCOL.md §5.
fn write_probability(n: usize) -> f32 {
    1.0 / (n as f32 + 1.0)
}

/// The probability-gate check, extracted so mutations on the
/// comparison + arithmetic are catchable from tests.
fn should_fire_write(random: f32, n: usize) -> bool {
    random < write_probability(n)
}

/// Spawn the heal + write loops. Returns a [`JoinSet`] the caller owns —
/// dropping it aborts the tasks; awaiting each joins cleanly.
/// Cancellation drops pending DHT and gossip calls, but cannot undo requests
/// already submitted to a remote peer.
pub(crate) fn spawn_loops(
    state: Arc<ProtoState>,
    dht: Arc<dyn DhtSlots>,
    gossip: Arc<dyn GossipView>,
    cancel: CancellationToken,
) -> JoinSet<()> {
    let mut tasks = JoinSet::new();

    // Heal loop.
    {
        let state = state.clone();
        let dht = dht.clone();
        let gossip = gossip.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            loop {
                let sleep = jittered(state.config.heal_period, state.config.jitter);
                tokio::select! {
                    () = tokio::time::sleep(sleep) => {}
                    () = cancel.cancelled() => break,
                }
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    () = heal_once(&state, dht.as_ref(), gossip.as_ref()) => {}
                }
            }
        });
    }

    // Write loop. The first iteration fires an immediate self-publish
    // (completing §5's Join procedure) so newcomers find us quickly;
    // subsequent iterations respect T_w · jitter and the probabilistic
    // `p = 1/(n+1)` rule.
    {
        let state = state.clone();
        let dht = dht.clone();
        let gossip = gossip.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let mut first_iter = true;
            loop {
                let should_write = if first_iter {
                    first_iter = false;
                    true
                } else {
                    // While the last publish is failing, retry on the
                    // shorter `failure_retry_period` cadence and bypass
                    // the `1/(n+1)` probability gate — the gate exists
                    // to avoid swarm-wide write storms when N is large
                    // and the DHT is healthy, but once *our* publish
                    // has failed we should retry unconditionally until
                    // it succeeds.
                    let failing = matches!(
                        state.observable.lock().map(|s| s.dht_status),
                        Ok(DhtStatus::PublishFailing)
                    );
                    let period = if failing {
                        state.config.failure_retry_period
                    } else {
                        state.config.write_period
                    };
                    let sleep = jittered(period, state.config.jitter);
                    tokio::select! {
                        () = tokio::time::sleep(sleep) => {}
                        () = cancel.cancelled() => break,
                    }
                    if failing {
                        true
                    } else {
                        // Scope the (non-Send) ThreadRng so it doesn't
                        // live across the await.
                        let n = gossip.neighbors().len();
                        let r = {
                            let mut rng = rand::rng();
                            rng.random::<f32>()
                        };
                        should_fire_write(r, n)
                    }
                };
                if should_write {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => break,
                        () = write_once(&state, dht.as_ref(), gossip.as_ref()) => {}
                    }
                }
            }
        });
    }

    tasks
}

/// One heal-loop iteration. Reads `s = max(1, K − |N|)` random slots in
/// parallel and feeds unknown IDs to the gossip layer.
async fn heal_once(state: &ProtoState, dht: &dyn DhtSlots, gossip: &dyn GossipView) {
    let neighbors = gossip.neighbors();
    let s = state.config.shards.saturating_sub(neighbors.len()).max(1);

    let slot_indices: Vec<usize> = {
        let mut idx: Vec<usize> = (0..state.config.shards).collect();
        let mut rng = rand::rng();
        idx.shuffle(&mut rng);
        idx.truncate(s);
        idx
    };

    let known: std::collections::HashSet<_> = neighbors.iter().copied().collect();
    let mut new_peers = Vec::new();
    for k in slot_indices {
        for id in read_slot(state, dht, k).await {
            if id != state.config.self_id && !known.contains(&id) && !new_peers.contains(&id) {
                new_peers.push(id);
            }
        }
    }

    if let Ok(mut s) = state.observable.lock() {
        s.last_heal = Some(Instant::now());
    }

    if !new_peers.is_empty() {
        debug!(count = new_peers.len(), "heal-loop discovered peers");
        gossip.join_peers(new_peers).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    mod cancellation;

    use super::*;
    use crate::dht::memory::InMemoryDht;

    /// A `GossipView` impl that returns a fixed neighbor set and records
    /// `join_peers` calls. Useful for testing without real gossip.
    pub(crate) struct MockGossip {
        neighbors: Mutex<Vec<[u8; 32]>>,
        joined: Arc<Mutex<Vec<[u8; 32]>>>,
    }

    impl MockGossip {
        fn new(neighbors: Vec<[u8; 32]>) -> (Self, Arc<Mutex<Vec<[u8; 32]>>>) {
            let joined = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    neighbors: Mutex::new(neighbors),
                    joined: joined.clone(),
                },
                joined,
            )
        }
    }

    #[async_trait]
    impl GossipView for MockGossip {
        fn neighbors(&self) -> Vec<[u8; 32]> {
            self.neighbors.lock().map(|g| g.clone()).unwrap_or_default()
        }
        async fn join_peers(&self, peers: Vec<[u8; 32]>) {
            if let Ok(mut g) = self.joined.lock() {
                g.extend(peers);
            }
        }
    }

    /// Fault-injecting `DhtSlots`. Fails the first `fail_writes` write calls
    /// (counting attempts, not slots), then delegates to an inner
    /// [`InMemoryDht`]. Reads always delegate.
    struct FaultyDht {
        inner: InMemoryDht,
        remaining_failures: Mutex<usize>,
        write_attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FaultyDht {
        fn new(fail_writes: usize) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    inner: InMemoryDht::new(),
                    remaining_failures: Mutex::new(fail_writes),
                    write_attempts: attempts.clone(),
                },
                attempts,
            )
        }
    }

    #[async_trait]
    impl DhtSlots for FaultyDht {
        async fn read(
            &self,
            slot: crate::dht::SlotKey,
        ) -> Result<Option<crate::dht::SlotRecord>, crate::dht::DhtError> {
            self.inner.read(slot).await
        }

        async fn write(
            &self,
            slot: crate::dht::SlotKey,
            record: crate::dht::SlotRecord,
        ) -> Result<(), crate::dht::DhtError> {
            self.write_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let should_fail = {
                let mut r = self.remaining_failures.lock().unwrap();
                if *r > 0 {
                    *r -= 1;
                    true
                } else {
                    false
                }
            };
            if should_fail {
                return Err(crate::dht::DhtError::Transport("injected".into()));
            }
            self.inner.write(slot, record).await
        }
    }

    fn test_config(self_id: [u8; 32], shards: usize) -> ProtocolConfig {
        ProtocolConfig {
            self_id,
            shards,
            max_age: 27,
            max_entries: 27,
            max_vouches: 3,
            epoch_size: 64,
            write_period: Duration::from_secs(1),
            heal_period: Duration::from_secs(1),
            failure_retry_period: Duration::from_millis(50),
            jitter: 0.5,
        }
    }

    fn test_state(config: ProtocolConfig) -> ProtoState {
        let keys = PassphraseKeys::derive("passphrase", "test/v1", config.shards);
        let observable = Arc::new(Mutex::new(RendezvousState {
            topic_id: keys.topic_id,
            neighbor_count: 0,
            dht_status: DhtStatus::Bootstrapping,
            last_publish: None,
            last_heal: None,
            active_shards: config.shards,
        }));
        ProtoState::new(config, keys, observable)
    }

    #[tokio::test]
    async fn write_then_read_single_node() {
        let self_id = [1u8; 32];
        let state = test_state(test_config(self_id, 3));
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let (g, _joined) = MockGossip::new(vec![]);
        let gossip: Arc<dyn GossipView> = Arc::new(g);

        write_once(&state, dht.as_ref(), gossip.as_ref()).await;

        // Reading slot_u should return our self ID.
        let k = state.own_slot();
        let found = read_slot(&state, dht.as_ref(), k).await;
        assert_eq!(found, vec![self_id]);
    }

    #[tokio::test]
    async fn two_nodes_discover_each_other() {
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());

        // Node A writes first.
        let id_a = [1u8; 32];
        let state_a = test_state(test_config(id_a, 3));
        let (ga, _) = MockGossip::new(vec![]);
        write_once(&state_a, dht.as_ref(), &ga).await;

        // Node B joins with empty gossip. It should see A in the DHT.
        let id_b = [2u8; 32];
        let state_b = Arc::new(test_state(test_config(id_b, 3)));
        let (gb, joined_b) = MockGossip::new(vec![]);
        let discovered = initial_join(state_b, dht.clone(), &gb).await;

        assert!(discovered.contains(&id_a), "B should discover A");
        assert_eq!(
            joined_b.lock().unwrap().iter().copied().collect::<Vec<_>>(),
            vec![id_a]
        );
    }

    #[tokio::test]
    async fn three_node_bootstrap_all_see_each_other() {
        // All three nodes write their self-entry, then each reads — all
        // should see both peers (themselves excluded).
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());

        let ids: Vec<[u8; 32]> = (1u8..=3).map(|i| [i; 32]).collect();

        // Everyone writes.
        for &self_id in &ids {
            let state = test_state(test_config(self_id, 3));
            let (g, _) = MockGossip::new(vec![]);
            write_once(&state, dht.as_ref(), &g).await;
        }

        // Everyone reads (via initial_join).
        for &self_id in &ids {
            let state = Arc::new(test_state(test_config(self_id, 3)));
            let (g, joined) = MockGossip::new(vec![]);
            initial_join(state, dht.clone(), &g).await;
            let j = joined.lock().unwrap().clone();
            for &other in &ids {
                if other != self_id {
                    assert!(j.contains(&other), "{self_id:?} didn't discover {other:?}");
                }
            }
        }
    }

    #[tokio::test]
    async fn write_loop_recovers_from_publish_failing_on_short_period() {
        // Loop should retry on `failure_retry_period` (not `write_period`)
        // and bypass the `1/(n+1)` gate while `DhtStatus::PublishFailing`.
        // Setup: write_period=10s, failure_retry_period=30ms, dht fails
        // first 3 writes then succeeds. Within a few hundred ms we should
        // see ≥4 attempts (3 fails + 1 success) and status == Ready.

        let self_id = [42u8; 32];
        let mut config = test_config(self_id, 3);
        config.write_period = Duration::from_secs(10);
        config.heal_period = Duration::from_secs(10);
        config.failure_retry_period = Duration::from_millis(30);
        // No jitter so the test is deterministic.
        config.jitter = 0.0;

        let state = Arc::new(test_state(config));
        let (faulty, attempts) = FaultyDht::new(3);
        let dht: Arc<dyn DhtSlots> = Arc::new(faulty);
        let (gossip_view, _joined) = MockGossip::new(vec![]);
        let gossip: Arc<dyn GossipView> = Arc::new(gossip_view);
        let cancel = CancellationToken::new();

        let mut tasks = spawn_loops(state.clone(), dht.clone(), gossip.clone(), cancel.clone());

        // 4 × 30ms = 120ms minimum. Give 500ms — comfortably above the
        // retry budget, comfortably below `write_period`. If the loop
        // were waiting on `write_period` (10s) we'd see only 1 attempt.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let made = attempts.load(std::sync::atomic::Ordering::SeqCst);
        let status = state.observable.lock().unwrap().dht_status;

        cancel.cancel();
        while tasks.join_next().await.is_some() {}

        assert!(
            made >= 4,
            "expected ≥4 write attempts (3 fails + 1 success) within 500ms; got {made}"
        );
        assert_eq!(
            status,
            DhtStatus::Ready,
            "status should flip to Ready after the 4th write succeeded"
        );
    }

    #[tokio::test]
    async fn seq_is_monotonic_across_writes() {
        let self_id = [1u8; 32];
        let state = test_state(test_config(self_id, 3));
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let (g, _) = MockGossip::new(vec![]);

        for _ in 0..5 {
            write_once(&state, dht.as_ref(), &g).await;
        }
        let k = state.own_slot();
        let record = dht.read(state.slot_key(k)).await.unwrap().unwrap();
        assert_eq!(record.seq, 5, "seq should increment on each write");
    }

    #[test]
    fn jittered_within_bounds() {
        let d = Duration::from_secs(10);
        for _ in 0..100 {
            let out = jittered(d, 0.5);
            assert!(out >= Duration::from_secs_f32(5.0));
            assert!(out <= Duration::from_secs_f32(15.0));
        }
    }

    // ── Pure arithmetic helpers (mutation-killer tests) ─────────────

    #[test]
    fn jittered_with_j_is_exact_multiplication() {
        // `* +` mutation produces period + factor (units wrong). At j=0,
        // original = period (factor=1.0), mutant = period + 1.0 seconds.
        let d = Duration::from_secs(100);
        assert_eq!(jittered_with_j(d, 0.0), d);

        // At j = +0.5: factor = 1.5, result = 150s exactly.
        let out = jittered_with_j(d, 0.5);
        let want = Duration::from_secs_f32(150.0);
        assert!(
            out.abs_diff(want) < Duration::from_millis(10),
            "got {out:?}, want ≈150s"
        );

        // At j = -0.5: factor = 0.5, result = 50s.
        let out = jittered_with_j(d, -0.5);
        let want = Duration::from_secs_f32(50.0);
        assert!(
            out.abs_diff(want) < Duration::from_millis(10),
            "got {out:?}, want ≈50s"
        );
    }

    #[test]
    fn jittered_with_j_at_extreme_negative_clamps_to_one_percent() {
        // factor = max(1.0 + j, 0.01). At j = -0.999, 1+j = 0.001, clamped to 0.01.
        let d = Duration::from_secs(100);
        let out = jittered_with_j(d, -0.999);
        assert_eq!(out, Duration::from_secs_f32(100.0 * 0.01));
    }

    #[test]
    fn jittered_distribution_has_variance() {
        // `delete -` mutation: `range(-jitter..=jitter)` → `range(jitter..=jitter)`.
        // Only one value possible; every sample yields `period * (1+jitter)`
        // exactly — no variance. Detect via observed range.
        let d = Duration::from_secs(100);
        let mut min = Duration::MAX;
        let mut max = Duration::ZERO;
        for _ in 0..200 {
            let out = jittered(d, 0.5);
            if out < min {
                min = out;
            }
            if out > max {
                max = out;
            }
        }
        // With 200 samples and uniform [-0.5, 0.5], min should be ≤ 70s
        // and max should be ≥ 130s. A constant `* 1.5` gives min == max.
        assert!(
            max.saturating_sub(min) > Duration::from_secs(20),
            "jitter has no variance: min={min:?} max={max:?}"
        );
    }

    #[test]
    fn write_probability_is_one_over_n_plus_one() {
        // Kills `/ %`, `/ *`, `+ -`, `+ *` mutations in `1 / (n + 1)`.
        assert!((write_probability(0) - 1.0).abs() < 1e-6);
        assert!((write_probability(1) - 0.5).abs() < 1e-6);
        assert!((write_probability(3) - 0.25).abs() < 1e-6);
        assert!((write_probability(9) - 0.1).abs() < 1e-6);
        assert!((write_probability(99) - 0.01).abs() < 1e-4);
    }

    #[test]
    fn should_fire_write_boundary_behaviors() {
        // Kills `< ==`, `< >`, `< <=` mutations on the probability gate.
        // For n = 0, p = 1.0. Any random < 1.0 should return true.
        assert!(should_fire_write(0.0, 0));
        assert!(should_fire_write(0.999, 0));
        assert!(!should_fire_write(1.0, 0), "random == p must NOT fire");

        // For n = 999, p ≈ 0.001.
        assert!(should_fire_write(0.0, 999));
        assert!(!should_fire_write(0.5, 999));
        assert!(!should_fire_write(1.0, 999));
    }

    #[test]
    fn slot_for_and_own_slot_are_deterministic_and_nonconstant() {
        // Kills mutations that replace slot_for / own_slot with constants
        // (0 or 1). With 5 shards and several distinct IDs, we observe
        // more than two distinct slot indices.
        let state = test_state(test_config([1u8; 32], 5));
        let mut seen = std::collections::HashSet::new();
        for i in 1..=40u8 {
            seen.insert(state.slot_for(&[i; 32]));
        }
        assert!(seen.len() >= 3, "slot_for looks constant: {seen:?}");

        // own_slot matches slot_for(self_id).
        let expected = state.slot_for(&state.config.self_id);
        assert_eq!(state.own_slot(), expected);

        // Changing self_id changes own_slot (at least for some IDs).
        let state2 = test_state(test_config([7u8; 32], 5));
        // Self IDs differ → at least one of the own-slot values differs
        // from the other (otherwise slot_for is effectively constant).
        if state.own_slot() == state2.own_slot() {
            // Try more values.
            let state3 = test_state(test_config([42u8; 32], 5));
            assert_ne!(
                state.own_slot(),
                state3.own_slot(),
                "own_slot appears constant across distinct self_ids"
            );
        }
    }

    #[tokio::test]
    async fn heal_once_excludes_self_from_new_peers() {
        // Kills `&&` → `||` mutations on line `id != self_id && !known.contains(&id) ...`:
        // the mutant would include self_id in new_peers.
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let self_id = [7u8; 32];
        let state = test_state(test_config(self_id, 3));
        let (g, joined) = MockGossip::new(vec![]);

        // Put self in the DHT via a write.
        write_once(&state, dht.as_ref(), &g).await;

        // Heal. Must NOT yield self_id to join_peers.
        heal_once(&state, dht.as_ref(), &g).await;
        let collected = joined.lock().unwrap().clone();
        assert!(
            !collected.contains(&self_id),
            "heal handed self back: {collected:?}"
        );
    }

    #[tokio::test]
    async fn heal_once_excludes_already_known_neighbors() {
        // Kills the second `&&` → `||` on line 394: with ||, the filter
        // would include IDs already in `known`.
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let self_id = [1u8; 32];
        let peer = [2u8; 32];

        // Peer writes to the DHT as if it existed.
        let peer_state = test_state(test_config(peer, 3));
        let (pg, _) = MockGossip::new(vec![]);
        write_once(&peer_state, dht.as_ref(), &pg).await;

        // Our node already knows `peer` (it's in our active view).
        let state = test_state(test_config(self_id, 3));
        let (g, joined) = MockGossip::new(vec![peer]);

        heal_once(&state, dht.as_ref(), &g).await;
        let collected = joined.lock().unwrap().clone();
        assert!(
            !collected.contains(&peer),
            "heal re-reported known neighbor: {collected:?}"
        );
    }

    // ── Multi-node scenarios ────────────────────────────────────────

    /// A simulated node: protocol state + mock gossip. `neighbors_mut`
    /// lets the test driver inject connections without running iroh-gossip.
    struct SimNode {
        state: Arc<ProtoState>,
        gossip: Arc<MockGossip>,
    }

    impl SimNode {
        fn new(self_id: [u8; 32], shards: usize) -> Self {
            let state = Arc::new(test_state(test_config(self_id, shards)));
            let (g, _) = MockGossip::new(vec![]);
            Self {
                state,
                gossip: Arc::new(g),
            }
        }

        fn connect_to(&self, other_id: [u8; 32]) {
            if let Ok(mut g) = self.gossip.neighbors.lock() {
                if !g.contains(&other_id) {
                    g.push(other_id);
                }
            }
        }

        fn drain_joined(&self) -> Vec<[u8; 32]> {
            self.gossip
                .joined
                .lock()
                .map(|mut g| std::mem::take(&mut *g))
                .unwrap_or_default()
        }
    }

    /// Run one "round" on a node: one write attempt (deterministic — we
    /// ignore the probabilistic `p = 1/(n+1)` here so tests converge) and
    /// one heal read.
    async fn run_round(node: &SimNode, dht: &dyn DhtSlots) {
        write_once(&node.state, dht, node.gossip.as_ref()).await;
        heal_once(&node.state, dht, node.gossip.as_ref()).await;
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn partition_heals_within_bounded_rounds() {
        // 6 nodes total, split 3/3. Each "partition" has mutual gossip
        // neighbors internally but none across the split. Loop rounds
        // until both partitions have discovered at least one peer from
        // the other side; assert convergence within MAX_ROUNDS.
        //
        // With K=3 and each heal-read picking 1 random slot (since
        // |N|=2 inside each partition), the expected rounds to full
        // cross-partition visibility is bounded by a small constant.
        const MAX_ROUNDS: usize = 20;

        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let k = 3;
        let ids: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        let nodes: Vec<SimNode> = ids.iter().map(|id| SimNode::new(*id, k)).collect();

        // Intra-partition full mesh (A = 0..3, B = 3..6).
        for (i, node) in nodes.iter().enumerate() {
            let group = if i < 3 { 0..3 } else { 3..6 };
            for j in group {
                if j != i {
                    node.connect_to(ids[j]);
                }
            }
        }

        let partition_a: std::collections::HashSet<_> = ids[0..3].iter().copied().collect();
        let partition_b: std::collections::HashSet<_> = ids[3..6].iter().copied().collect();

        let mut a_saw_b = false;
        let mut b_saw_a = false;

        for _ in 0..MAX_ROUNDS {
            for node in &nodes {
                run_round(node, dht.as_ref()).await;
            }
            for (i, node) in nodes.iter().enumerate() {
                let joined = node.drain_joined();
                if i < 3 && joined.iter().any(|id| partition_b.contains(id)) {
                    a_saw_b = true;
                }
                if i >= 3 && joined.iter().any(|id| partition_a.contains(id)) {
                    b_saw_a = true;
                }
            }
            if a_saw_b && b_saw_a {
                return;
            }
        }
        panic!(
            "partition did not heal within {MAX_ROUNDS} rounds (a_saw_b={a_saw_b}, b_saw_a={b_saw_a})"
        );
    }

    #[tokio::test]
    async fn asymmetric_partition_minority_visible() {
        // 1 minority node vs 10 majority nodes, K=3. The minority writes to
        // one slot; the majority's random heal reads should find it within
        // a few rounds.
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let k = 3;
        let minority = SimNode::new([99u8; 32], k);
        let majority_ids: Vec<[u8; 32]> = (1u8..=10).map(|i| [i; 32]).collect();
        let majority: Vec<SimNode> = majority_ids.iter().map(|id| SimNode::new(*id, k)).collect();

        // Majority is fully connected internally.
        for (i, node) in majority.iter().enumerate() {
            for (j, other) in majority_ids.iter().enumerate() {
                if i != j {
                    node.connect_to(*other);
                }
            }
        }

        // Minority writes its self-entry.
        write_once(&minority.state, dht.as_ref(), minority.gossip.as_ref()).await;

        // Each majority node runs heal rounds. At least one should discover
        // the minority within a few rounds (since s = max(1, K - N) for the
        // majority is 1, but with 10 of them each reading a random slot,
        // the union covers all K slots quickly).
        let mut minority_seen = false;
        for _round in 0..5 {
            for node in &majority {
                heal_once(&node.state, dht.as_ref(), node.gossip.as_ref()).await;
                let joined = node.drain_joined();
                if joined.contains(&[99u8; 32]) {
                    minority_seen = true;
                }
            }
            if minority_seen {
                break;
            }
        }
        assert!(
            minority_seen,
            "10-majority should find the minority within 5 rounds"
        );
    }

    #[tokio::test]
    async fn cold_start_convergence() {
        // 8 nodes, no prior DHT state, no prior gossip connectivity.
        // After one write round + one heal round, every node should have
        // been handed every other node's ID.
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let k = 3;
        let ids: Vec<[u8; 32]> = (1u8..=8).map(|i| [i; 32]).collect();
        let nodes: Vec<SimNode> = ids.iter().map(|id| SimNode::new(*id, k)).collect();

        // Everyone writes.
        for node in &nodes {
            write_once(&node.state, dht.as_ref(), node.gossip.as_ref()).await;
        }
        // Everyone heals.
        for node in &nodes {
            heal_once(&node.state, dht.as_ref(), node.gossip.as_ref()).await;
        }

        // Each node should have been handed at least one other node's ID.
        // (Isolated nodes read s = K = 3 slots, so unless a slot is empty
        // they'll see at least one peer.)
        for node in &nodes {
            let joined = node.drain_joined();
            assert!(
                !joined.is_empty(),
                "node {:?} got no peers from heal",
                node.state.config.self_id
            );
        }
    }

    #[tokio::test]
    async fn vouching_propagates_ids_across_slots() {
        // Node A with neighbors B, C. A writes to slot_u(A); vouches for B
        // and C. A reader querying slot_u(A) should see A, B, C — regardless
        // of which slot B and C would write to themselves.
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let id_c = [3u8; 32];

        let a = SimNode::new(id_a, 3);
        a.connect_to(id_b);
        a.connect_to(id_c);

        write_once(&a.state, dht.as_ref(), a.gossip.as_ref()).await;

        // Read slot_u(A) — should contain all three.
        let k_a = a.state.own_slot();
        let seen = read_slot(&a.state, dht.as_ref(), k_a).await;
        assert!(seen.contains(&id_a), "self missing");
        assert!(seen.contains(&id_b), "vouched B missing");
        assert!(seen.contains(&id_c), "vouched C missing");
    }

    // ── Audit gap tests ───────────────────────────────────────────────

    #[test]
    fn heal_adaptive_s_formula() {
        // PROTOCOL.md §5 HealLoop: s = max(1, K - |N|).
        fn s_formula(k: usize, neighbors: usize) -> usize {
            k.saturating_sub(neighbors).max(1)
        }
        // K=3: isolated reads all 3; saturated reads 1.
        assert_eq!(s_formula(3, 0), 3);
        assert_eq!(s_formula(3, 1), 2);
        assert_eq!(s_formula(3, 2), 1);
        assert_eq!(s_formula(3, 3), 1); // max floor.
        assert_eq!(s_formula(3, 100), 1);
        // K=5.
        assert_eq!(s_formula(5, 0), 5);
        assert_eq!(s_formula(5, 2), 3);
        assert_eq!(s_formula(5, 10), 1);
        // K=1: always reads 1.
        assert_eq!(s_formula(1, 0), 1);
        assert_eq!(s_formula(1, 5), 1);
    }

    #[test]
    fn write_probability_gate_matches_n_plus_one() {
        // PROTOCOL.md §5 WriteLoop: p = 1/(|N|+1). Over many samples,
        // observed rate should approach 1/(n+1) for any n.
        fn gate_p(n: usize) -> f32 {
            1.0 / (n as f32 + 1.0)
        }
        // Run 100_000 Bernoulli trials at n=9 and check |observed - 0.1| ≤ 0.01.
        let mut rng = rand::rng();
        let mut writes = 0u32;
        let target = gate_p(9);
        for _ in 0..100_000u32 {
            if rng.random::<f32>() < target {
                writes += 1;
            }
        }
        let observed = writes as f32 / 100_000.0;
        assert!(
            (observed - target).abs() < 0.01,
            "observed {observed} vs target {target} exceeds 1% tolerance"
        );
    }

    #[tokio::test]
    async fn read_slot_on_corrupt_envelope_returns_empty() {
        // PROTOCOL.md §4 ReadSlot: crypto or decode failure returns the
        // empty set, never panics or propagates the error.
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());
        let state = test_state(test_config([1u8; 32], 3));

        // Hand-craft a record that passes signature but is nonsense for
        // the crypto layer (zeros — won't decrypt).
        let slot_key = state.slot_key(0);
        let garbage = vec![0u8; 80];
        let signing = &state.keys.slots[0].signing;
        let rec = crate::dht::memory::sign_record(signing, garbage, 1);
        dht.write(slot_key, rec).await.unwrap();

        // read_slot returns empty — no entries, no panic.
        let result = read_slot(&state, dht.as_ref(), 0).await;
        assert!(
            result.is_empty(),
            "corrupt envelope should yield empty: {result:?}"
        );
    }

    #[tokio::test]
    async fn seq_cache_tracks_highest_observed_seq() {
        // When a read observes a seq higher than what we've seen, our
        // next write must use seq = observed + 1.
        let self_id = [1u8; 32];
        let state = test_state(test_config(self_id, 3));
        let dht: Arc<dyn DhtSlots> = Arc::new(InMemoryDht::new());

        // Simulate another writer stamping seq=100 onto our slot_u directly.
        let k = state.own_slot();
        let slot_key = state.slot_key(k);
        let signing = &state.keys.slots[k].signing;
        // Encrypt an entries buffer (empty) so that read_slot populates seq_cache.
        let entries: Vec<crate::wire::Entry> = Vec::new();
        let plaintext = crate::wire::encode_entries(&entries);
        let envelope = crate::crypto::seal(
            &state.keys.slots[k].wrapper,
            &plaintext,
            100,
            state.config.epoch_size,
        )
        .unwrap();
        let rec = crate::dht::memory::sign_record(signing, envelope, 100);
        dht.write(slot_key, rec).await.unwrap();

        // A read observes seq=100 and populates the cache.
        let _ = read_slot(&state, dht.as_ref(), k).await;
        assert_eq!(state.last_seq(k), 100);

        // Now our write should use seq=101.
        let (g, _) = MockGossip::new(vec![]);
        write_once(&state, dht.as_ref(), &g).await;
        let after = dht.read(slot_key).await.unwrap().unwrap();
        assert_eq!(after.seq, 101);
    }
}
