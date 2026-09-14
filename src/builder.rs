//! Builder for advanced [`Rendezvous`] configuration.
//!
//! Use this when the top-level [`Rendezvous::join`] convenience isn't enough:
//! to supply your own iroh `Endpoint`, a stable `SecretKey`, or to override
//! the algorithm parameters from §2 of the design doc.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::{Endpoint, SecretKey};
use iroh_gossip::Gossip;
use tokio_util::sync::CancellationToken;

use crate::dht::mainline::MainlineDht;
use crate::dht::{DhtSlots, SlotKey};
use crate::gossip_glue;
use crate::keys::PassphraseKeys;
use crate::protocol::{ProtoState, ProtocolConfig};
use crate::state::{DhtStatus, RendezvousState};
use crate::{Error, Rendezvous, Result};

/// K — number of DHT shards.
pub const DEFAULT_SHARDS: usize = 3;
/// B — max entries per slot. Dictated by BEP 44's 1000-byte `v` budget plus
/// crypto overhead; not tunable without breaking the wire format.
pub const DEFAULT_MAX_ENTRIES: usize = 27;
/// A_max — max logical age before eviction.
pub const DEFAULT_MAX_AGE: u8 = 27;
/// V — max vouches per write.
pub const DEFAULT_MAX_VOUCHES: usize = 3;
/// E — writes per wrapper-key epoch.
pub const DEFAULT_EPOCH_WRITES: u64 = 64;
/// T_w — mean write-loop period.
pub const DEFAULT_WRITE_PERIOD: Duration = Duration::from_secs(300);
/// T_h — mean heal-loop period.
pub const DEFAULT_HEAL_PERIOD: Duration = Duration::from_secs(30);
/// T_f — write-loop period while `DhtStatus::PublishFailing`. Used in
/// place of `T_w` until a publish succeeds; the probability gate is also
/// skipped during recovery so every tick attempts a write. Bounds the
/// recovery latency from a transient DHT failure to roughly this period
/// (± jitter) regardless of neighbor count.
pub const DEFAULT_FAILURE_RETRY_PERIOD: Duration = Duration::from_secs(15);
/// σ — jitter factor (± fraction of the period).
pub const DEFAULT_JITTER: f32 = 0.5;

/// Advanced builder.
pub struct Builder {
    passphrase: Option<String>,
    app_salt: Option<String>,
    endpoint: Option<Endpoint>,
    gossip: Option<Gossip>,
    secret_key: Option<SecretKey>,
    shards: usize,
    max_age: u8,
    max_entries: usize,
    max_vouches: usize,
    epoch_size: u64,
    write_period: Duration,
    heal_period: Duration,
    failure_retry_period: Duration,
    jitter: f32,
    wait_for_first_neighbor: Option<Duration>,
    /// Test-only: inject a custom DhtSlots backend (e.g., InMemoryDht).
    /// Gated behind the `test-support` feature.
    #[cfg(feature = "test-support")]
    dht_backend: Option<Arc<dyn DhtSlots>>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            passphrase: None,
            app_salt: None,
            endpoint: None,
            gossip: None,
            secret_key: None,
            shards: DEFAULT_SHARDS,
            max_age: DEFAULT_MAX_AGE,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_vouches: DEFAULT_MAX_VOUCHES,
            epoch_size: DEFAULT_EPOCH_WRITES,
            write_period: DEFAULT_WRITE_PERIOD,
            heal_period: DEFAULT_HEAL_PERIOD,
            failure_retry_period: DEFAULT_FAILURE_RETRY_PERIOD,
            jitter: DEFAULT_JITTER,
            wait_for_first_neighbor: None,
            #[cfg(feature = "test-support")]
            dht_backend: None,
        }
    }
}

impl Builder {
    /// Set the shared passphrase. Required.
    #[must_use]
    pub fn passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = Some(passphrase.to_owned());
        self
    }

    /// Set the application salt. Required. An opaque label identifying the
    /// application + major version, e.g. `"my-app/v1"`. Different apps (or
    /// different major versions) should use different salts so their DHT
    /// surfaces don't collide.
    #[must_use]
    pub fn app_salt(mut self, salt: &str) -> Self {
        self.app_salt = Some(salt.to_owned());
        self
    }

    /// Bring your own iroh [`Endpoint`]. Overrides `secret_key` if both are
    /// supplied. This mode owns the endpoint's accept loop and closes the
    /// endpoint on shutdown. Use [`Self::gossip`] to share a Router instead.
    #[must_use]
    pub fn endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self.gossip = None;
        self
    }

    /// Uses an application's gossip actor without taking over its runtime.
    ///
    /// `gossip` must have been created from `endpoint`. Iroh-gossip does not
    /// expose the actor's endpoint, so this requirement cannot be checked.
    /// The caller must route the gossip ALPN to this actor. Rendezvous neither
    /// accepts connections nor closes the actor or endpoint in this mode.
    /// Overrides an earlier [`Self::endpoint`] or [`Self::secret_key`] choice.
    #[must_use]
    pub fn gossip(mut self, endpoint: Endpoint, gossip: Gossip) -> Self {
        self.endpoint = Some(endpoint);
        self.gossip = Some(gossip);
        self
    }

    /// Use a specific secret key for the internally-built endpoint.
    /// Ignored if [`Self::endpoint`] is also set. Default: fresh random key.
    #[must_use]
    pub fn secret_key(mut self, key: SecretKey) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Override the shard count `K`. Default 3.
    #[must_use]
    pub fn shards(mut self, k: usize) -> Self {
        self.shards = k;
        self
    }

    /// Override `A_max`. Default 27 (equal to `B`).
    #[must_use]
    pub fn max_age(mut self, a: u8) -> Self {
        self.max_age = a;
        self
    }

    /// Override `V`. Default 3.
    #[must_use]
    pub fn max_vouches(mut self, v: usize) -> Self {
        self.max_vouches = v;
        self
    }

    /// Override `E` — writes per wrapper-key epoch. Default 64.
    #[must_use]
    pub fn epoch_writes(mut self, e: u64) -> Self {
        self.epoch_size = e;
        self
    }

    /// Override `T_w`. Default 5 minutes.
    #[must_use]
    pub fn write_period(mut self, period: Duration) -> Self {
        self.write_period = period;
        self
    }

    /// Override `T_h`. Default 30 seconds.
    #[must_use]
    pub fn heal_period(mut self, period: Duration) -> Self {
        self.heal_period = period;
        self
    }

    /// Override `T_f` — the write-loop period used while
    /// [`DhtStatus::PublishFailing`](crate::state::DhtStatus::PublishFailing).
    /// Default 15 seconds.
    ///
    /// While failing, the probability gate `1/(n+1)` is bypassed and a
    /// write is attempted every tick. Returning to
    /// [`DhtStatus::Ready`](crate::state::DhtStatus::Ready) on a
    /// successful publish restores the steady-state `write_period`
    /// cadence and re-engages the gate.
    #[must_use]
    pub fn failure_retry_period(mut self, period: Duration) -> Self {
        self.failure_retry_period = period;
        self
    }

    /// Override `σ`. Default 0.5 (± 50%).
    #[must_use]
    pub fn jitter(mut self, sigma: f32) -> Self {
        self.jitter = sigma;
        self
    }

    /// If set, `build` will block up to `timeout` waiting for the first
    /// gossip neighbor to join. Returns `Ok` either way (a lone node is a
    /// valid start state). Default: don't wait.
    #[must_use]
    pub fn wait_for_first_neighbor(mut self, timeout: Option<Duration>) -> Self {
        self.wait_for_first_neighbor = timeout;
        self
    }

    /// Test-support: inject a custom `DhtSlots` backend. Primary use case
    /// is swapping the production Mainline DHT for an [`InMemoryDht`] in
    /// integration tests.
    ///
    /// Gated behind the `test-support` feature. Not part of the stable
    /// public API.
    ///
    /// [`InMemoryDht`]: crate::sim::InMemoryDht
    #[cfg(feature = "test-support")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-support")))]
    #[must_use]
    pub fn dht_backend(mut self, backend: Arc<dyn DhtSlots>) -> Self {
        self.dht_backend = Some(backend);
        self
    }

    /// Build the configured [`Rendezvous`] and start its DHT loops.
    pub async fn build(self) -> Result<Rendezvous> {
        let passphrase = self.passphrase.ok_or(Error::EmptyPassphrase)?;
        if passphrase.is_empty() {
            return Err(Error::EmptyPassphrase);
        }
        let app_salt = self.app_salt.ok_or(Error::EmptyAppSalt)?;
        if app_salt.is_empty() {
            return Err(Error::EmptyAppSalt);
        }
        if self.shards == 0 {
            return Err(Error::InvalidShardCount);
        }
        if self.max_age == 0 {
            return Err(Error::InvalidMaxAge);
        }

        // Derive all keys.
        let keys = PassphraseKeys::derive(&passphrase, &app_salt, self.shards);
        let topic_id = keys.topic_id;

        let observable = Arc::new(Mutex::new(RendezvousState {
            topic_id,
            neighbor_count: 0,
            dht_status: DhtStatus::Bootstrapping,
            last_publish: None,
            last_heal: None,
            active_shards: self.shards,
        }));

        let cancel = CancellationToken::new();
        let mut tasks = tokio::task::JoinSet::new();

        // Build the iroh + gossip layer.
        let layer = gossip_glue::build(
            gossip_glue::GossipConfig {
                endpoint: self.endpoint,
                gossip: self.gossip,
                secret_key: self.secret_key,
                topic_id,
                bootstrap_peers: Vec::new(),
            },
            observable.clone(),
            cancel.clone(),
            &mut tasks,
        )
        .await?;

        let layer = Arc::new(layer);
        let self_id = *layer.endpoint.id().as_bytes();

        // Build the DHT client. With `test-support`, the caller may have
        // injected an alternative backend; otherwise use Mainline.
        #[cfg(feature = "test-support")]
        let dht: Arc<dyn DhtSlots> = match self.dht_backend {
            Some(b) => b,
            None => build_mainline_dht(&keys)?,
        };
        #[cfg(not(feature = "test-support"))]
        let dht = build_mainline_dht(&keys)?;

        let config = ProtocolConfig {
            self_id,
            shards: self.shards,
            max_age: self.max_age,
            max_entries: self.max_entries,
            max_vouches: self.max_vouches,
            epoch_size: self.epoch_size,
            write_period: self.write_period,
            heal_period: self.heal_period,
            failure_retry_period: self.failure_retry_period,
            jitter: self.jitter,
        };

        let proto_state = Arc::new(ProtoState::new(config, keys, observable.clone()));
        let gossip_view: Arc<dyn crate::protocol::GossipView> = layer.clone();

        // Initial Join: read all slots, feed discovered peers, then update
        // iroh-gossip so it starts dialing.
        let discovered =
            crate::protocol::initial_join(proto_state.clone(), dht.clone(), gossip_view.as_ref())
                .await;
        // Log-only branch — mutations here don't affect correctness.
        log_bootstrap_result(&discovered);

        // Start the background loops.
        let protocol_tasks = crate::protocol::spawn_loops(
            proto_state.clone(),
            dht.clone(),
            gossip_view.clone(),
            cancel.clone(),
        );

        let rendezvous = Rendezvous::__new(
            layer,
            dht,
            proto_state,
            observable,
            cancel,
            tasks,
            protocol_tasks,
        );

        // Optional: block briefly until we have at least one neighbor.
        if let Some(timeout) = self.wait_for_first_neighbor {
            wait_for_first_neighbor(&rendezvous, timeout).await;
        }

        Ok(rendezvous)
    }
}

/// Poll the [`Rendezvous`] state until either a neighbor shows up or the
/// timeout elapses. Both `<` / `>` comparisons here have equivalent-mutant
/// variants that only a live gossip stack can distinguish:
///
/// * `start.elapsed() < timeout` vs `<=`: differs only at the precise
///   boundary instant, practically unobservable.
/// * `neighbor_count > 0` vs `< 0`: `neighbor_count` is `usize`, so
///   `< 0` is never true — behaviorally equivalent to `> 0` whenever no
///   neighbors appear (e.g., under `test-support` with `InMemoryDht`).
///
/// Timing semantics (that the loop eventually returns, and bails early
/// on a real neighbor) are covered by:
/// * `builder::tests::build_wait_timeout_elapses_without_neighbors` —
///   asserts elapsed ≥ timeout when the InMemoryDht produces no neighbor.
/// * `tests/two_node_bootstrap.rs` — bridge smoke + live convergence.
#[mutants::skip]
async fn wait_for_first_neighbor(rendezvous: &Rendezvous, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if rendezvous.state().neighbor_count > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[mutants::skip] // Log-only branch, no correctness impact.
fn log_bootstrap_result(discovered: &[[u8; 32]]) {
    if discovered.is_empty() {
        tracing::info!("rendezvous: no peers in DHT yet (first node?)");
    } else {
        tracing::info!(
            count = discovered.len(),
            "rendezvous: bootstrapped from DHT"
        );
    }
}

/// Build the mainline-DHT impl with signing keys for every slot.
#[mutants::skip] // Covered by bridge integration + nightly `mainline-live` feature.
fn build_mainline_dht(keys: &PassphraseKeys) -> Result<Arc<dyn DhtSlots>> {
    let dht = mainline::Dht::client().map_err(|e| Error::Dht(Box::new(e)))?;
    let async_dht = dht.as_async();
    let signers: Vec<(SlotKey, mainline::SigningKey)> = keys
        .slots
        .iter()
        .map(|sk| {
            // Re-construct a mainline SigningKey from the 32-byte seed.
            // ed25519-dalek and mainline's re-export share the same types.
            let slot_key = SlotKey(sk.verifying.to_bytes());
            let seed = sk.signing.to_bytes();
            let signing = mainline::SigningKey::from_bytes(&seed);
            (slot_key, signing)
        })
        .collect();
    Ok(Arc::new(MainlineDht::new(async_dht, signers)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Inner tests with direct field access — used to pin every Builder
    //! setter's effect for cargo-mutants. Without these, setter mutations
    //! (replace body with `Default::default()`) can only be caught
    //! indirectly through build(), which is expensive + requires network.

    use super::*;

    #[test]
    fn passphrase_setter_stores_value() {
        let b = Builder::default().passphrase("abc");
        assert_eq!(b.passphrase.as_deref(), Some("abc"));
    }

    #[test]
    fn app_salt_setter_stores_value() {
        let b = Builder::default().app_salt("my-app/v1");
        assert_eq!(b.app_salt.as_deref(), Some("my-app/v1"));
    }

    #[test]
    fn endpoint_setter_stores_value() {
        // Cheap construction: make a real endpoint on an ephemeral port.
        // The setter just stores it — no network activity.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = rt.block_on(async {
            iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                .bind()
                .await
                .unwrap()
        });
        let before = Builder::default();
        let after = Builder::default().endpoint(endpoint);
        assert!(before.endpoint.is_none());
        assert!(after.endpoint.is_some());
        rt.block_on(async { after.endpoint.unwrap().close().await });
    }

    #[test]
    fn secret_key_setter_stores_value() {
        let sk = iroh::SecretKey::generate();
        let before = Builder::default();
        let after = Builder::default().secret_key(sk);
        assert!(before.secret_key.is_none());
        assert!(after.secret_key.is_some());
    }

    #[test]
    fn shards_setter_stores_exact_value() {
        assert_eq!(Builder::default().shards(7).shards, 7);
        assert_eq!(Builder::default().shards(1).shards, 1);
        assert_eq!(Builder::default().shards(99).shards, 99);
    }

    #[test]
    fn max_age_setter_stores_exact_value() {
        assert_eq!(Builder::default().max_age(42).max_age, 42);
        assert_eq!(Builder::default().max_age(1).max_age, 1);
        assert_eq!(Builder::default().max_age(255).max_age, 255);
    }

    #[test]
    fn max_vouches_setter_stores_exact_value() {
        assert_eq!(Builder::default().max_vouches(5).max_vouches, 5);
        assert_eq!(Builder::default().max_vouches(0).max_vouches, 0);
    }

    #[test]
    fn epoch_writes_setter_stores_exact_value() {
        assert_eq!(Builder::default().epoch_writes(128).epoch_size, 128);
        assert_eq!(Builder::default().epoch_writes(1).epoch_size, 1);
    }

    #[test]
    fn write_period_setter_stores_exact_value() {
        let d = Duration::from_secs(777);
        assert_eq!(Builder::default().write_period(d).write_period, d);
    }

    #[test]
    fn heal_period_setter_stores_exact_value() {
        let d = Duration::from_secs(13);
        assert_eq!(Builder::default().heal_period(d).heal_period, d);
    }

    #[test]
    fn failure_retry_period_setter_stores_exact_value() {
        let d = Duration::from_millis(42);
        assert_eq!(
            Builder::default()
                .failure_retry_period(d)
                .failure_retry_period,
            d
        );
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn dht_backend_setter_stores_value() {
        use std::sync::Arc;

        use crate::sim::InMemoryDht;
        let dht = Arc::new(InMemoryDht::new());
        let before = Builder::default();
        let after = Builder::default().dht_backend(dht);
        assert!(before.dht_backend.is_none());
        assert!(after.dht_backend.is_some());
    }

    #[test]
    fn jitter_setter_stores_exact_value() {
        let b = Builder::default().jitter(0.25);
        assert!((b.jitter - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn wait_for_first_neighbor_stores_value() {
        assert_eq!(
            Builder::default()
                .wait_for_first_neighbor(None)
                .wait_for_first_neighbor,
            None
        );
        let some = Some(Duration::from_secs(5));
        assert_eq!(
            Builder::default()
                .wait_for_first_neighbor(some)
                .wait_for_first_neighbor,
            some
        );
    }

    #[test]
    fn setter_preserves_previous_values() {
        // Regression: a setter mutated to `Default::default()` would wipe
        // the passphrase set on the previous line. We chain two setters
        // and assert the first's effect survives.
        let b = Builder::default().passphrase("keep").max_vouches(9);
        assert_eq!(b.passphrase.as_deref(), Some("keep"));
        assert_eq!(b.max_vouches, 9);

        let b = Builder::default().app_salt("a").epoch_writes(17);
        assert_eq!(b.app_salt.as_deref(), Some("a"));
        assert_eq!(b.epoch_size, 17);

        let b = Builder::default()
            .passphrase("p")
            .wait_for_first_neighbor(Some(Duration::from_secs(3)));
        assert_eq!(b.passphrase.as_deref(), Some("p"));
        assert_eq!(b.wait_for_first_neighbor, Some(Duration::from_secs(3)));
    }

    // ── Validation boundary tests (kill `<`/`>`/`<=`/`>=` mutants in build()). ──

    #[tokio::test]
    async fn build_shards_zero_is_invalid_shard_count() {
        let r = Builder::default()
            .passphrase("p")
            .app_salt("a")
            .shards(0)
            .build()
            .await;
        assert!(matches!(r, Err(Error::InvalidShardCount)));
    }

    #[tokio::test]
    async fn build_shards_one_is_not_invalid() {
        // Kills `== 0 → >= 0` and `== 0 → <= 0` equivalents — shards(1)
        // must NOT return InvalidShardCount.
        //
        // Uses test-support's in-memory DHT so no network.
        #[cfg(feature = "test-support")]
        {
            use std::sync::Arc;

            use crate::sim::InMemoryDht;
            let dht = Arc::new(InMemoryDht::new());
            let r = Builder::default()
                .passphrase("p")
                .app_salt("a")
                .shards(1)
                .dht_backend(dht)
                .build()
                .await;
            assert!(r.is_ok(), "shards=1 should build successfully");
            if let Ok(rv) = r {
                rv.shutdown().await;
            }
        }
    }

    #[tokio::test]
    async fn build_max_age_zero_is_invalid() {
        let r = Builder::default()
            .passphrase("p")
            .app_salt("a")
            .max_age(0)
            .build()
            .await;
        assert!(matches!(r, Err(Error::InvalidMaxAge)));
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn build_max_age_one_is_not_invalid() {
        use std::sync::Arc;

        use crate::sim::InMemoryDht;
        let dht = Arc::new(InMemoryDht::new());
        let r = Builder::default()
            .passphrase("p")
            .app_salt("a")
            .max_age(1)
            .dht_backend(dht)
            .build()
            .await;
        assert!(r.is_ok(), "max_age=1 should build successfully");
        if let Ok(rv) = r {
            rv.shutdown().await;
        }
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn build_wait_timeout_elapses_without_neighbors() {
        // Covers the timing semantics of wait_for_first_neighbor's loop.
        // With InMemoryDht there are no iroh neighbors; the loop must run
        // until the timeout instead of returning immediately.
        use std::sync::Arc;
        use std::time::Instant;

        use crate::sim::InMemoryDht;

        let dht = Arc::new(InMemoryDht::new());
        let timeout = Duration::from_millis(300);
        let t0 = Instant::now();
        let r = Builder::default()
            .passphrase("p")
            .app_salt("a")
            .dht_backend(dht)
            .wait_for_first_neighbor(Some(timeout))
            .build()
            .await;
        let elapsed = t0.elapsed();
        assert!(r.is_ok());
        // Polling interval is 100ms; give 250ms as a generous floor.
        assert!(
            elapsed >= Duration::from_millis(250),
            "build returned too fast: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "build took too long: {elapsed:?}"
        );
        if let Ok(rv) = r {
            rv.shutdown().await;
        }
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn build_wait_none_does_not_block() {
        // Without `wait_for_first_neighbor`, build should return in well under a second.
        use std::sync::Arc;
        use std::time::Instant;

        use crate::sim::InMemoryDht;

        let dht = Arc::new(InMemoryDht::new());
        let t0 = Instant::now();
        let r = Builder::default()
            .passphrase("p")
            .app_salt("a")
            .dht_backend(dht)
            .build()
            .await;
        let elapsed = t0.elapsed();
        assert!(r.is_ok());
        assert!(
            elapsed < Duration::from_secs(2),
            "build took too long: {elapsed:?}"
        );
        if let Ok(rv) = r {
            rv.shutdown().await;
        }
    }
}
