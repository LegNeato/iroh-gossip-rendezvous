//! Shared Router lifecycle without public relay or DHT access.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, RelayMode};
use iroh_gossip::{Gossip, TopicId};
use iroh_gossip_rendezvous::Builder;
use iroh_gossip_rendezvous::sim::InMemoryDht;

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
