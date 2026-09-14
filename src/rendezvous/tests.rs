#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode};
use iroh_gossip::api::Event;
use tokio::sync::broadcast::{Receiver, error::RecvError, error::TryRecvError};

use crate::sim::InMemoryDht;
use crate::{Builder, Rendezvous};

async fn rendezvous() -> Rendezvous {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    Builder::default()
        .passphrase("event-lifetime-test")
        .app_salt("rendezvous/tests/events")
        .endpoint(endpoint)
        .dht_backend(Arc::new(InMemoryDht::new()))
        .build()
        .await
        .unwrap()
}

async fn assert_closed(receiver: &mut Receiver<Event>) {
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("event source closes"),
        Err(RecvError::Closed),
    );
}

#[tokio::test]
async fn shutdown_closes_current_and_later_subscriptions() {
    let rendezvous = rendezvous().await;
    let mut first = rendezvous.subscribe();
    let mut second = rendezvous.subscribe();
    assert_eq!(first.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(second.try_recv(), Err(TryRecvError::Empty));

    rendezvous.shutdown().await;

    assert_closed(&mut first).await;
    assert_closed(&mut second).await;
    assert_closed(&mut rendezvous.subscribe()).await;
}

#[tokio::test]
async fn failed_actor_closes_subscriptions_and_stops_maintenance() {
    let rendezvous = rendezvous().await;
    let mut events = rendezvous.subscribe();
    assert_eq!(events.try_recv(), Err(TryRecvError::Empty));

    rendezvous.layer.actor.shutdown().await.unwrap();

    assert_closed(&mut events).await;
    assert!(rendezvous.cancel.is_cancelled());
    assert_closed(&mut rendezvous.subscribe()).await;
    rendezvous.shutdown().await;
}

#[tokio::test]
async fn dropping_handle_closes_the_event_source() {
    let rendezvous = rendezvous().await;
    let mut events = rendezvous.subscribe();
    let endpoint = rendezvous.endpoint().clone();

    drop(rendezvous);

    assert_closed(&mut events).await;
    endpoint.close().await;
}
