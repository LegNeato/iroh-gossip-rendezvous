#![allow(clippy::expect_used)]

use core::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::{MockGossip, test_config, test_state};
use crate::dht::{DhtError, DhtSlots, SlotKey, SlotRecord};
use crate::protocol::spawn_loops;

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum Block {
    ReadsAfter(usize),
    Writes,
}

struct BlockedDht {
    block: Block,
    reads: AtomicUsize,
    writes: AtomicUsize,
    dropped: AtomicUsize,
    started: Notify,
}

impl BlockedDht {
    fn new(block: Block) -> Self {
        Self {
            block,
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            started: Notify::new(),
        }
    }

    async fn block(&self) {
        struct PendingOperation<'a>(&'a AtomicUsize);

        impl Drop for PendingOperation<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let _operation = PendingOperation(&self.dropped);
        self.started.notify_one();
        pending::<()>().await;
    }

    async fn wait_for_operation(&self) {
        timeout(TIMEOUT, self.started.notified())
            .await
            .expect("maintenance reaches the blocked operation");
    }
}

#[async_trait]
impl DhtSlots for BlockedDht {
    async fn read(&self, _slot: SlotKey) -> Result<Option<SlotRecord>, DhtError> {
        let previous = self.reads.fetch_add(1, Ordering::SeqCst);
        if matches!(self.block, Block::ReadsAfter(allowed) if previous >= allowed) {
            self.block().await;
        }
        Ok(None)
    }

    async fn write(&self, _slot: SlotKey, _record: SlotRecord) -> Result<(), DhtError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if matches!(self.block, Block::Writes) {
            self.block().await;
        }
        Ok(())
    }
}

fn start(dht: Arc<BlockedDht>, cancel: CancellationToken, heal_period: Duration) -> JoinSet<()> {
    let mut config = test_config([7; 32], 1);
    config.heal_period = heal_period;
    config.write_period = Duration::from_secs(60);
    config.jitter = 0.0;
    let (gossip, _) = MockGossip::new(Vec::new());
    spawn_loops(Arc::new(test_state(config)), dht, Arc::new(gossip), cancel)
}

async fn drain(tasks: &mut JoinSet<()>) {
    timeout(TIMEOUT, async {
        let mut completed = 0;
        while let Some(result) = tasks.join_next().await {
            result.expect("maintenance exits without aborting or panicking");
            completed += 1;
        }
        assert_eq!(completed, 2);
    })
    .await
    .expect("both maintenance loops stop without DHT completion");
}

#[tokio::test(start_paused = true)]
async fn cancellation_drops_a_pending_heal_read() {
    let dht = Arc::new(BlockedDht::new(Block::ReadsAfter(1)));
    let cancel = CancellationToken::new();
    let mut tasks = start(Arc::clone(&dht), cancel.clone(), Duration::from_secs(1));
    dht.wait_for_operation().await;
    assert_eq!(dht.reads.load(Ordering::SeqCst), 2);
    assert_eq!(dht.writes.load(Ordering::SeqCst), 1);

    cancel.cancel();
    drain(&mut tasks).await;
    assert_eq!(dht.dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn cancellation_drops_a_pending_publish_read() {
    let dht = Arc::new(BlockedDht::new(Block::ReadsAfter(0)));
    let cancel = CancellationToken::new();
    let mut tasks = start(Arc::clone(&dht), cancel.clone(), Duration::from_secs(60));
    dht.wait_for_operation().await;
    assert_eq!(dht.reads.load(Ordering::SeqCst), 1);
    assert_eq!(dht.writes.load(Ordering::SeqCst), 0);

    cancel.cancel();
    drain(&mut tasks).await;
    assert_eq!(dht.dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn cancellation_drops_a_pending_write() {
    let dht = Arc::new(BlockedDht::new(Block::Writes));
    let cancel = CancellationToken::new();
    let mut tasks = start(Arc::clone(&dht), cancel.clone(), Duration::from_secs(60));
    dht.wait_for_operation().await;
    assert_eq!(dht.reads.load(Ordering::SeqCst), 1);
    assert_eq!(dht.writes.load(Ordering::SeqCst), 1);

    cancel.cancel();
    drain(&mut tasks).await;
    assert_eq!(dht.dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn stopped_maintenance_does_not_start_an_operation() {
    let dht = Arc::new(BlockedDht::new(Block::ReadsAfter(0)));
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut tasks = start(Arc::clone(&dht), cancel, Duration::from_secs(1));

    drain(&mut tasks).await;
    assert_eq!(dht.reads.load(Ordering::SeqCst), 0);
    assert_eq!(dht.writes.load(Ordering::SeqCst), 0);
    assert_eq!(dht.dropped.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn graceful_shutdown_drains_pending_reads_and_writes() {
    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode};

    for block in [Block::ReadsAfter(1), Block::Writes] {
        let dht = Arc::new(BlockedDht::new(block));
        let endpoint = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let rendezvous = crate::Builder::default()
            .passphrase("pending-maintenance-test")
            .app_salt("rendezvous/tests/cancellation")
            .shards(1)
            .heal_period(Duration::from_secs(60))
            .endpoint(endpoint.clone())
            .dht_backend(dht.clone())
            .build()
            .await
            .unwrap();
        dht.wait_for_operation().await;

        timeout(TIMEOUT, rendezvous.shutdown())
            .await
            .expect("graceful shutdown does not await a stalled DHT");
        assert_eq!(dht.dropped.load(Ordering::SeqCst), 1);
        assert!(endpoint.is_closed());
    }
}
