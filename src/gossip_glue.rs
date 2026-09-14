//! Integration with iroh-gossip: endpoint build, topic subscription, and the
//! event fan-out task that keeps [`RendezvousState`] live and lets multiple
//! consumers read gossip events via
//! [`Rendezvous::subscribe`](crate::Rendezvous::subscribe).
//!
//! Design: we subscribe to the topic exactly once internally; a background
//! task drains the `GossipReceiver` and broadcasts every `Event` to a
//! `tokio::sync::broadcast` channel. Callers get their own subscriber via
//! `Rendezvous::subscribe` and never compete for the underlying receiver.
//! Internal state (`neighbor_count`, membership) stays live for the full
//! lifetime of the handle.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_lite::StreamExt;
use iroh::{Endpoint, PublicKey, SecretKey};
use iroh_gossip::TopicId;
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use iroh_gossip::net::Gossip;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::protocol::GossipView;
use crate::state::RendezvousState;
use crate::{Error, Result};

/// Internal handle to the iroh-gossip layer. Shared as `Arc<GossipLayer>`
/// between the [`Rendezvous`] handle and the protocol loops.
pub(crate) struct GossipLayer {
    pub(crate) endpoint: Endpoint,
    pub(crate) actor: Gossip,
    pub(crate) sender: GossipSender,
    pub(crate) topic_id: TopicId,
    pub(crate) event_tx: tokio::sync::broadcast::WeakSender<Event>,
    owns_runtime: bool,
    neighbors: Arc<Mutex<HashSet<PublicKey>>>,
}

#[async_trait]
impl GossipView for GossipLayer {
    // Thin forwarder to internal state. Equivalence-class mutations like
    // "return vec![]" vs "return vec![[0;32]]" can only be distinguished
    // by tests that spin up a real iroh gossip actor — covered by the
    // integration tests under `tests/two_node_bootstrap.rs` when CI has
    // network access, and by the bridge's end-to-end two-node smoke test.
    #[mutants::skip]
    fn neighbors(&self) -> Vec<[u8; 32]> {
        let Ok(guard) = self.neighbors.lock() else {
            return Vec::new();
        };
        guard.iter().map(|id| *id.as_bytes()).collect()
    }

    // Forwards to `iroh_gossip::api::GossipSender::join_peers`. The `!=`
    // guard is a self-filter; exercising it requires a running iroh stack.
    // Covered indirectly by the integration tests + bridge smoke tests.
    #[mutants::skip]
    async fn join_peers(&self, peers: Vec<[u8; 32]>) {
        let keys: Vec<PublicKey> = peers
            .iter()
            .filter_map(|p| PublicKey::from_bytes(p).ok())
            .filter(|pk| *pk != self.endpoint.id())
            .collect();
        if keys.is_empty() {
            return;
        }
        if let Err(e) = self.sender.join_peers(keys).await {
            debug!(error = %e, "gossip join_peers failed");
        }
    }
}

/// Inputs to [`build`].
pub(crate) struct GossipConfig {
    pub endpoint: Option<Endpoint>,
    pub gossip: Option<Gossip>,
    pub secret_key: Option<SecretKey>,
    pub topic_id: TopicId,
    pub bootstrap_peers: Vec<PublicKey>,
}

/// Build the endpoint (if not supplied) and subscribe to the topic. Spawns
/// the accept loop and the event fan-out task into `tasks`.
pub(crate) async fn build(
    cfg: GossipConfig,
    observable: Arc<Mutex<RendezvousState>>,
    cancel: CancellationToken,
    tasks: &mut JoinSet<()>,
) -> Result<GossipLayer> {
    let endpoint = match cfg.endpoint {
        Some(ep) => ep,
        None => {
            let secret = cfg.secret_key.unwrap_or_else(SecretKey::generate);
            Endpoint::builder(iroh::endpoint::presets::N0)
                .secret_key(secret)
                .alpns(vec![iroh_gossip::ALPN.to_vec()])
                .bind()
                .await
                .map_err(|e| Error::Endpoint(Box::new(e)))?
        }
    };

    let owns_runtime = cfg.gossip.is_none();
    let actor = cfg
        .gossip
        .unwrap_or_else(|| Gossip::builder().spawn(endpoint.clone()));

    let topic = actor
        .subscribe(cfg.topic_id, cfg.bootstrap_peers)
        .await
        .map_err(|e| Error::Gossip(Box::new(e)))?;
    let (sender, receiver) = topic.split();

    let neighbors: Arc<Mutex<HashSet<PublicKey>>> = Arc::new(Mutex::new(HashSet::new()));
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel::<Event>(1024);

    if owns_runtime {
        spawn_accept_loop(endpoint.clone(), actor.clone(), cancel.clone(), tasks);
    }
    let event_weak = event_tx.downgrade();
    spawn_event_task(
        receiver,
        neighbors.clone(),
        observable,
        event_tx,
        cancel,
        tasks,
    );

    Ok(GossipLayer {
        endpoint,
        actor,
        sender,
        topic_id: cfg.topic_id,
        event_tx: event_weak,
        owns_runtime,
        neighbors,
    })
}

/// Closes a standalone runtime. Shared runtimes belong to the application.
#[mutants::skip] // Async iroh-gossip + endpoint shutdown — unit-testable
// only via real iroh stacks. Covered by `tests/two_node_bootstrap.rs`'s
// shutdown paths + the bridge smoke test.
pub(crate) async fn shutdown(layer: &GossipLayer) {
    if layer.owns_runtime {
        let _ = layer.actor.shutdown().await;
        layer.endpoint.close().await;
    }
}

// ── Internal tasks ──────────────────────────────────────────────────────

// The spawn-* functions below start async tasks that drive a real iroh
// endpoint. Their behavior can only be observed via a live gossip swarm;
// mutation testing them would require a deterministic-scheduler mock of
// iroh-gossip — out of scope for this crate. Covered by integration tests
// + nightly `mainline-live` lane + the bridge's two-node smoke test.
#[mutants::skip]
fn spawn_accept_loop(
    endpoint: Endpoint,
    gossip: Gossip,
    cancel: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    tasks.spawn(async move {
        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => incoming,
                () = cancel.cancelled() => break,
            };
            let Some(incoming) = incoming else { break };
            let gossip = gossip.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let alpn = conn.alpn();
                if *alpn == *iroh_gossip::ALPN {
                    if let Err(e) = gossip.handle_connection(conn).await {
                        debug!(error = %e, "gossip handle_connection");
                    }
                } else {
                    debug!(?alpn, "unexpected ALPN for gossip endpoint");
                }
            });
        }
        debug!("accept loop stopped");
    });
}

#[mutants::skip] // See spawn_accept_loop's note.
fn spawn_event_task(
    mut receiver: GossipReceiver,
    neighbors: Arc<Mutex<HashSet<PublicKey>>>,
    observable: Arc<Mutex<RendezvousState>>,
    event_tx: tokio::sync::broadcast::Sender<Event>,
    cancel: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    tasks.spawn(async move {
        let mut clean_exit = false;
        loop {
            let next = tokio::select! {
                ev = receiver.next() => ev,
                () = cancel.cancelled() => { clean_exit = true; break; }
            };
            let event = match next {
                Some(Ok(ev)) => ev,
                Some(Err(e)) => {
                    error!(error = %e, "gossip receiver error");
                    break;
                }
                None => break,
            };

            match &event {
                Event::NeighborUp(id) => {
                    if let Ok(mut g) = neighbors.lock() {
                        g.insert(*id);
                        if let Ok(mut s) = observable.lock() {
                            s.neighbor_count = g.len();
                        }
                    }
                }
                Event::NeighborDown(id) => {
                    if let Ok(mut g) = neighbors.lock() {
                        g.remove(id);
                        if let Ok(mut s) = observable.lock() {
                            s.neighbor_count = g.len();
                        }
                    }
                }
                Event::Received(_) | Event::Lagged => {}
            }

            // Fan out to user subscribers. Error only if no receivers — that's fine.
            let _ = event_tx.send(event);
        }
        if clean_exit {
            debug!("gossip event task stopped (cancelled)");
        } else {
            warn!("gossip event task stopped unexpectedly");
            cancel.cancel();
        }
    });
}
