//! Public [`Rendezvous`] handle — the keep-alive anchor for DHT maintenance
//! and the surface callers interact with.

use std::sync::{Arc, Mutex};

use iroh::{Endpoint, PublicKey};
use iroh_gossip::TopicId;
use iroh_gossip::api::{Event, GossipSender};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::dht::DhtSlots;
use crate::gossip_glue::{self, GossipLayer};
use crate::protocol::ProtoState;
use crate::state::RendezvousState;
use crate::{Builder, Error, Result};

/// Handle to a live rendezvous.
///
/// Hold this alive for as long as you want the DHT maintenance loops to
/// run. Dropping it cancels the loops; the swarm will drift off the DHT
/// as entries age out. Call [`Rendezvous::shutdown`] for a graceful exit
/// (cancel + await + close endpoint).
///
/// `Rendezvous` is not `Clone`. If you need shared access across tasks,
/// wrap in `Arc`.
pub struct Rendezvous {
    layer: Arc<GossipLayer>,
    _dht: Arc<dyn DhtSlots>,
    _proto: Arc<ProtoState>,
    observable: Arc<Mutex<RendezvousState>>,
    cancel: CancellationToken,
    tasks: Mutex<Option<(JoinSet<()>, JoinSet<()>)>>,
}

impl Rendezvous {
    /// One-call join. Equivalent to
    /// `Rendezvous::builder().passphrase(…).app_salt(…).build().await`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyPassphrase`] / [`Error::EmptyAppSalt`] if
    /// either argument is empty, or wraps an underlying iroh/iroh-gossip/DHT
    /// failure if the network layer can't start.
    pub async fn join(passphrase: &str, app_salt: &str) -> Result<Self> {
        Builder::default()
            .passphrase(passphrase)
            .app_salt(app_salt)
            .build()
            .await
    }

    /// Advanced configuration builder. See [`Builder`] for all knobs.
    #[must_use]
    #[mutants::skip] // `Builder::default()` and `Default::default()` here
    // produce identical values — this is a semantically equivalent mutant.
    // The inner builder-tests module exhaustively pins all default field
    // values, so correctness is covered.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Crate-private constructor used by the builder.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn __new(
        layer: Arc<GossipLayer>,
        dht: Arc<dyn DhtSlots>,
        proto: Arc<ProtoState>,
        observable: Arc<Mutex<RendezvousState>>,
        cancel: CancellationToken,
        gossip_tasks: JoinSet<()>,
        protocol_tasks: JoinSet<()>,
    ) -> Self {
        Self {
            layer,
            _dht: dht,
            _proto: proto,
            observable,
            cancel,
            tasks: Mutex::new(Some((gossip_tasks, protocol_tasks))),
        }
    }

    /// The iroh gossip sender for this topic. Clone it cheaply and move
    /// clones into other tasks.
    #[must_use]
    pub fn sender(&self) -> &GossipSender {
        &self.layer.sender
    }

    /// Convenience broadcast. Equivalent to `sender().broadcast(bytes)`.
    ///
    /// # Errors
    ///
    /// Wraps `iroh_gossip::api::ApiError` into [`Error::Gossip`].
    #[mutants::skip] // Thin forwarder to `iroh_gossip::api::GossipSender::broadcast`.
    // Requires a live gossip swarm to observe mutations; covered by the
    // bridge integration smoke test.
    pub async fn broadcast(&self, bytes: bytes::Bytes) -> Result<()> {
        self.layer
            .sender
            .broadcast(bytes)
            .await
            .map_err(|e| Error::Gossip(Box::new(e)))
    }

    /// Subscribe to the gossip event stream. Each call returns a fresh
    /// [`tokio::sync::broadcast::Receiver`] — multiple consumers work.
    /// Lagging receivers may miss events; handle `Err(RecvError::Lagged)` or
    /// use a generous read cadence.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.layer.event_tx.subscribe()
    }

    /// Underlying iroh [`Endpoint`]. Share it through [`Builder::gossip`] when
    /// an application Router accepts other protocols on the same port.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.layer.endpoint
    }

    /// This node's [`PublicKey`] (endpoint ID).
    #[must_use]
    pub fn node_id(&self) -> PublicKey {
        self.layer.endpoint.id()
    }

    /// Gossip topic ID.
    #[must_use]
    pub fn topic_id(&self) -> TopicId {
        self.layer.topic_id
    }

    /// Snapshot of current runtime state. Cheap — just clones a small struct.
    #[must_use]
    pub fn state(&self) -> RendezvousState {
        self.observable
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Graceful shutdown. Cancels the background loops, awaits their clean
    /// exit, then closes a standalone actor and endpoint. Shared runtimes
    /// supplied through [`Builder::gossip`] remain open. Drop this handle and
    /// caller-owned gossip sender clones to release the topic fully.
    #[mutants::skip] // Async shutdown of tokio JoinSets + iroh endpoint;
    // exercised by `tests/two_node_bootstrap.rs::drop_cancels_background_tasks`
    // and the bridge smoke test.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let take = self.tasks.lock().map(|mut g| g.take()).ok().flatten();
        if let Some((mut gossip_tasks, mut protocol_tasks)) = take {
            while gossip_tasks.join_next().await.is_some() {}
            while protocol_tasks.join_next().await.is_some() {}
        }
        gossip_glue::shutdown(&self.layer).await;
        debug!("rendezvous shutdown complete");
    }
}

impl Drop for Rendezvous {
    #[mutants::skip] // Fire-and-forget cancellation; tested indirectly by
    // `tests/two_node_bootstrap.rs::drop_cancels_background_tasks`.
    fn drop(&mut self) {
        // Non-graceful: fire the cancel and let the runtime abort the tasks
        // when they hit their next yield. For graceful exit, callers should
        // use `shutdown()`.
        self.cancel.cancel();
    }
}
