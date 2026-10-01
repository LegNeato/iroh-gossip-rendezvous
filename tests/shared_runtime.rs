//! Shared Router lifecycle without public relay or DHT access.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, RelayMode};
use iroh_gossip::api::Event;
use iroh_gossip::{Gossip, TopicId};
use iroh_gossip_rendezvous::sim::InMemoryDht;
use iroh_gossip_rendezvous::{Builder, Rendezvous};
use tokio::sync::broadcast::Receiver;

const ECHO_ALPN: &[u8] = b"rendezvous/tests/echo/1";
const TIMEOUT: Duration = Duration::from_secs(5);

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

fn builder() -> Builder {
    Builder::default()
        .passphrase("shared-runtime-test")
        .app_salt("rendezvous/tests/shared-runtime")
        .dht_backend(Arc::new(InMemoryDht::new()))
}

#[derive(Debug)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let message = recv.read_to_end(64).await.map_err(AcceptError::from_err)?;
        send.write_all(&message)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

async fn echo(client: &Endpoint, address: EndpointAddr) {
    tokio::time::timeout(TIMEOUT, async {
        let connection = client.connect(address, ECHO_ALPN).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"shared").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"shared");
        connection.close(0u32.into(), b"done");
    })
    .await
    .expect("echo completes on the application Router");
}

#[tokio::test]
async fn shared_shutdown_keeps_other_protocols_and_actor_alive() {
    let endpoint = endpoint().await;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .accept(ECHO_ALPN, Echo)
        .spawn();
    let rendezvous = builder()
        .gossip(endpoint.clone(), gossip.clone())
        .build()
        .await
        .unwrap();
    let client = self::endpoint().await;

    echo(&client, endpoint.addr()).await;
    rendezvous.shutdown().await;
    rendezvous.shutdown().await;
    drop(rendezvous);
    assert!(!endpoint.is_closed());
    let topic = gossip.subscribe(TopicId::from_bytes([3; 32]), vec![]).await;
    assert!(topic.is_ok(), "the application still owns the gossip actor");
    echo(&client, endpoint.addr()).await;

    client.close().await;
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn standalone_shutdown_closes_the_supplied_endpoint() {
    let endpoint = endpoint().await;
    let rendezvous = builder().endpoint(endpoint.clone()).build().await.unwrap();
    assert!(!endpoint.is_closed());

    rendezvous.shutdown().await;
    assert!(endpoint.is_closed());
}

#[tokio::test]
async fn selecting_endpoint_after_gossip_restores_standalone_mode() {
    let endpoint = endpoint().await;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let rendezvous = builder()
        .gossip(endpoint.clone(), gossip.clone())
        .endpoint(endpoint.clone())
        .build()
        .await
        .unwrap();

    rendezvous.shutdown().await;
    assert!(endpoint.is_closed());
    gossip.shutdown().await.unwrap();
}

#[tokio::test]
async fn dropping_shared_rendezvous_does_not_close_application_runtime() {
    let endpoint = endpoint().await;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let rendezvous = builder()
        .gossip(endpoint.clone(), gossip.clone())
        .build()
        .await
        .unwrap();

    drop(rendezvous);
    tokio::task::yield_now().await;
    assert!(!endpoint.is_closed());
    assert!(
        gossip
            .subscribe(TopicId::from_bytes([4; 32]), vec![])
            .await
            .is_ok()
    );

    gossip.shutdown().await.unwrap();
    endpoint.close().await;
}

async fn wait_for_neighbors(a: &Rendezvous, b: &Rendezvous) {
    tokio::time::timeout(TIMEOUT, async {
        while a.state().neighbor_count == 0 || b.state().neighbor_count == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both shared runtimes discover a gossip neighbor");
}

async fn assert_received(events: &mut Receiver<Event>, expected: &[u8]) {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Event::Received(message) = events.recv().await.unwrap() {
                assert_eq!(message.content.as_ref(), expected);
                break;
            }
        }
    })
    .await
    .expect("the application Router carries the gossip message");
}

#[tokio::test]
async fn shared_runtime_discovers_broadcasts_and_preserves_other_subscriptions() {
    let endpoint_a = endpoint().await;
    let endpoint_b = endpoint().await;
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(endpoint_a.addr());
    lookup.add_endpoint_info(endpoint_b.addr());
    endpoint_a.address_lookup().unwrap().add(lookup.clone());
    endpoint_b.address_lookup().unwrap().add(lookup);

    let gossip_a = Gossip::builder().spawn(endpoint_a.clone());
    let gossip_b = Gossip::builder().spawn(endpoint_b.clone());
    let router_a = Router::builder(endpoint_a.clone())
        .accept(iroh_gossip::ALPN, gossip_a.clone())
        .spawn();
    let router_b = Router::builder(endpoint_b.clone())
        .accept(iroh_gossip::ALPN, gossip_b.clone())
        .spawn();
    let dht = Arc::new(InMemoryDht::new());
    let shared_builder = || {
        builder()
            .shards(1)
            .heal_period(Duration::from_millis(20))
            .write_period(Duration::from_millis(50))
            .jitter(0.0)
            .dht_backend(dht.clone())
    };
    let a = shared_builder()
        .gossip(endpoint_a.clone(), gossip_a.clone())
        .build()
        .await
        .unwrap();
    let b = shared_builder()
        .gossip(endpoint_b.clone(), gossip_b.clone())
        .build()
        .await
        .unwrap();
    wait_for_neighbors(&a, &b).await;

    let mut events = b.subscribe();
    a.broadcast(Bytes::from_static(b"shared-message"))
        .await
        .unwrap();
    assert_received(&mut events, b"shared-message").await;

    // Attach to an already active topic, including application-owned handles.
    let application_a = gossip_a.subscribe(a.topic_id(), vec![]).await.unwrap();
    let application_b = gossip_b.subscribe(b.topic_id(), vec![]).await.unwrap();
    let other_a = shared_builder()
        .gossip(endpoint_a.clone(), gossip_a)
        .build()
        .await
        .unwrap();
    let other_b = shared_builder()
        .gossip(endpoint_b.clone(), gossip_b)
        .build()
        .await
        .unwrap();
    wait_for_neighbors(&other_a, &other_b).await;

    a.shutdown().await;
    b.shutdown().await;
    assert!(!endpoint_a.is_closed());
    assert!(!endpoint_b.is_closed());
    drop((a, b));

    let mut other_events = other_b.subscribe();
    other_a
        .broadcast(Bytes::from_static(b"remaining-topic"))
        .await
        .unwrap();
    assert_received(&mut other_events, b"remaining-topic").await;

    other_a.shutdown().await;
    other_b.shutdown().await;
    drop((other_a, other_b, application_a, application_b));
    router_a.shutdown().await.unwrap();
    router_b.shutdown().await.unwrap();
}
