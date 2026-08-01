//! Shared test harness for Sub-Phase 2B mix-node integration tests.
//!
//! Spins up real mix-node and relay processes on real loopback TCP ports
//! — deliberately **not** `axum-test`'s mocked in-process transport,
//! which isn't reachable by a separate `reqwest` client. Mix nodes must
//! reach each other (and the relay) over genuine HTTP: the next-hop
//! address is a literal `host:port` string recovered from the Sphinx
//! packet itself (see `parda_protocol::mixnet` module docs), and
//! `mixing::forward`/`mixing::deliver` use real `reqwest` calls, exactly
//! as the production daemon does.

use std::time::Duration;

use parda_mixnode::{app, MixNodeState};
use parda_protocol::mixnet::{self, MixNodeDescriptor};
use parda_relay::store::{RelayStore, SharedRelayStore};

pub struct RunningRelay {
    pub base_url: String,
    pub store: SharedRelayStore,
}

pub async fn spawn_relay() -> RunningRelay {
    let store = RelayStore::open_ephemeral();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind ephemeral relay port");
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let store_for_server = store.clone();
    tokio::spawn(async move {
        axum::serve(listener, parda_relay::app(store_for_server))
            .await
            .expect("test relay server error");
    });
    RunningRelay { base_url, store }
}

/// Spawn a real `parda-mixnode` daemon (the actual production router,
/// `parda_mixnode::app`) on an ephemeral loopback port.
pub async fn spawn_mixnode(relay_base_url: &str) -> MixNodeDescriptor {
    let (secret, public) = mixnet::generate_node_keypair();
    let state = MixNodeState::new(secret, relay_base_url.to_string());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind ephemeral mix node port");
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app(state))
            .await
            .expect("test mix node server error");
    });
    MixNodeDescriptor {
        address,
        public_key: public,
    }
}

/// Poll `store.drain(recipient_id)` until it returns a non-empty result,
/// or panic after `timeout`. Used instead of a fixed sleep so tests run
/// as fast as delivery actually completes, not as slow as a worst-case
/// guess.
pub async fn wait_for_delivery(
    store: &SharedRelayStore,
    recipient_id: &str,
    timeout: Duration,
) -> Vec<parda_relay::models::StoredEnvelope> {
    let start = tokio::time::Instant::now();
    loop {
        let drained = store.drain(recipient_id).await;
        if !drained.is_empty() {
            return drained;
        }
        if start.elapsed() > timeout {
            panic!("timed out after {timeout:?} waiting for delivery to {recipient_id:?}");
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Sub-Phase 4.5A: poll `store.fetch_pull(rendezvous_token)` until a
/// stage exists for it (even an empty one — `stage_pull` always inserts
/// a row, regardless of whether the recipient's queue was non-empty),
/// or panic after `timeout`. This is the receive-path's arrival signal,
/// symmetric to [`wait_for_delivery`] for the send path — the moment a
/// stage exists is the moment the pull request's mix-routed leg actually
/// reached `/v1/pulls`, which is exactly the timing this sub-phase's
/// permutation test needs to observe.
pub async fn wait_for_pull_arrival(
    store: &SharedRelayStore,
    rendezvous_token: &str,
    timeout: Duration,
) {
    let start = tokio::time::Instant::now();
    loop {
        // A direct existence check that does NOT consume the stage (so
        // it doesn't race with anything else that might also want it) —
        // `fetch_pull` clears on read, so poll via a cheap re-stage-safe
        // path: attempt fetch, and if present, we're done; if the poll
        // itself is what claims it, that's fine here since nothing else
        // in this test ever calls fetch_pull for the same token.
        if store.fetch_pull(rendezvous_token).await.is_some() {
            return;
        }
        if start.elapsed() > timeout {
            panic!("timed out after {timeout:?} waiting for pull arrival (token {rendezvous_token})");
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
