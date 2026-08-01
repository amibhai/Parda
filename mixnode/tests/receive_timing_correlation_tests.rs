//! Sub-Phase 4.5A timing-correlation statistical test — the receive-path
//! counterpart to `timing_correlation_tests.rs`'s send-path proof, held
//! to the identical methodology per the brief's explicit requirement
//! ("the same permutation-test rigor that proved the send path, applied
//! symmetrically, not a weaker proxy test"). See
//! `docs/phase4.5a-receive-path-design.md` for the full design note this
//! test is the deliverable gate for.
//!
//! ## Scope, precisely
//!
//! This test exercises **leg 1 only** (the Sphinx-wrapped pull request,
//! `PULL_DESTINATION_TAG`) — packets are built directly via
//! `mixnet::build_packet_to`, the same way the send-path test builds
//! envelope packets directly rather than going through the full
//! `SessionManager`/`MixTransport` stack. Leg 2 (`GET /v1/pulls/{token}`)
//! is a direct, unmixed connection by design (see the design note §3) —
//! there is no timing-correlation question to ask about a single direct
//! hop the way there is about a multi-hop mix path, so this test
//! (rightly) doesn't attempt to cover it; its own exposure is already
//! stated precisely in the design note and `docs/THREAT_MODEL.md`, not
//! something a permutation test would meaningfully bound further.
//!
//! ## Method
//!
//! Identical to `timing_correlation_tests.rs`: Spearman rank correlation
//! between send order (client's POST to the first hop) and arrival order
//! (the relay's `/v1/pulls` receipt, detected via
//! `common::wait_for_pull_arrival`), tested against a permutation-test
//! null distribution built from random re-pairings. See that file's
//! module docs for why rank correlation (not raw-timestamp correlation)
//! is the right statistic — the same reasoning applies unchanged here.

mod common;

use std::time::{Duration, Instant};

use parda_protocol::mixnet::{self, PullRequest};
use rand::seq::SliceRandom;

const NUM_MIX_NODES: usize = 5;
const PATH_LENGTH: usize = 3;
const AVG_HOP_DELAY_MS: u64 = 250;
const NUM_FLOWS: usize = 8;
const SEND_STAGGER_MS: u64 = 1;
const NUM_PERMUTATIONS: usize = 5_000;
const P_VALUE_THRESHOLD: f64 = 0.005;

/// Rank-transform (0-indexed, ascending) — identical to the send-path
/// test's helper (duplicated rather than shared across test binaries,
/// which don't share code except via `mod common`).
fn rank(xs: &[f64]) -> Vec<f64> {
    let mut order: Vec<usize> = (0..xs.len()).collect();
    order.sort_by(|&a, &b| xs[a].partial_cmp(&xs[b]).unwrap());
    let mut ranks = vec![0.0; xs.len()];
    for (r, &i) in order.iter().enumerate() {
        ranks[i] = r as f64;
    }
    ranks
}

fn pearson_r(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;
    let (mut cov, mut var_x, mut var_y) = (0.0, 0.0, 0.0);
    for i in 0..xs.len() {
        let dx = xs[i] - mean_x;
        let dy = ys[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }
    if var_x == 0.0 || var_y == 0.0 {
        0.0
    } else {
        cov / (var_x.sqrt() * var_y.sqrt())
    }
}

fn permutation_p_value(send: &[f64], arrival: &[f64], num_permutations: usize) -> f64 {
    let send_ranks = rank(send);
    let arrival_ranks = rank(arrival);
    let r_true = pearson_r(&send_ranks, &arrival_ranks).abs();

    let mut rng = rand::thread_rng();
    let mut shuffled = arrival_ranks.clone();
    let mut count_ge = 0usize;
    for _ in 0..num_permutations {
        shuffled.shuffle(&mut rng);
        if pearson_r(&send_ranks, &shuffled).abs() >= r_true {
            count_ge += 1;
        }
    }
    count_ge as f64 / num_permutations as f64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_pull_request_entry_to_arrival_timing_does_not_leak_flow_pairing_above_chance() {
    let relay = common::spawn_relay().await;

    let mut nodes = Vec::with_capacity(NUM_MIX_NODES);
    for _ in 0..NUM_MIX_NODES {
        nodes.push(common::spawn_mixnode(&relay.base_url).await);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let topology = mixnet::MixTopology::new(nodes);
    let http = reqwest::Client::new();

    // One PullRequest (fresh recipient + token) per flow, generated up
    // front so the arrival-watcher tasks know exactly which token to
    // watch for before anything is sent — same "start watching before
    // sending" discipline as the send-path test, so no arrival can race
    // ahead of its poll task.
    let requests: Vec<PullRequest> = (0..NUM_FLOWS)
        .map(|i| PullRequest::new(format!("flow-recipient-{i}")))
        .collect();

    let mut arrival_tasks = Vec::with_capacity(NUM_FLOWS);
    for request in &requests {
        let store = relay.store.clone();
        let token = request.rendezvous_token.clone();
        arrival_tasks.push(tokio::spawn(async move {
            common::wait_for_pull_arrival(&store, &token, Duration::from_secs(10)).await;
            Instant::now()
        }));
    }

    let base = Instant::now();
    let mut send_times = Vec::with_capacity(NUM_FLOWS);
    for request in &requests {
        let request_bytes = serde_json::to_vec(request).unwrap();
        let path = topology.choose_path(PATH_LENGTH).unwrap();
        let packet_bytes = mixnet::build_packet_to(
            &request_bytes,
            &path,
            Duration::from_millis(AVG_HOP_DELAY_MS),
            mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
            mixnet::PULL_DESTINATION_TAG,
        )
        .unwrap();

        let url = format!("http://{}/mix/packet", path[0].address);
        let send_time = Instant::now();
        http.post(&url)
            .body(packet_bytes)
            .send()
            .await
            .expect("first hop must be reachable")
            .error_for_status()
            .expect("first hop must accept a well-formed pull-request packet");
        send_times.push(send_time.duration_since(base).as_secs_f64());

        tokio::time::sleep(Duration::from_millis(SEND_STAGGER_MS)).await;
    }

    let mut arrival_times = Vec::with_capacity(NUM_FLOWS);
    for task in arrival_tasks {
        let t = task.await.expect("arrival-watcher task panicked");
        arrival_times.push(t.duration_since(base).as_secs_f64());
    }

    let p_value = permutation_p_value(&send_times, &arrival_times, NUM_PERMUTATIONS);
    assert!(
        p_value > P_VALUE_THRESHOLD,
        "pull-request send-time/arrival-time correlation for the true flow pairing \
         (p = {p_value:.4}) is a significant outlier against {NUM_PERMUTATIONS} random \
         re-pairings — an adversary watching only entry/exit timestamps could distinguish the \
         real pairing from chance at the tested scale ({NUM_FLOWS} flows, {PATH_LENGTH}-hop \
         paths, {AVG_HOP_DELAY_MS}ms avg per-hop delay)"
    );
}

/// Sanity check distinct from the timing claim above: confirms the
/// relay's `/v1/pulls` staging endpoint never reveals `recipient_id` to
/// anything watching only the wire-visible request — the pull-request
/// packet's *own* payload carries `recipient_id` (the relay legitimately
/// needs it, same as it already sees `recipient_id` for every send —
/// design note §5), but nothing about *that* is new. What's under test
/// here is narrower and specific to this sub-phase: the URL/path the
/// client's own leg-2 retrieval hits carries no such thing.
#[tokio::test]
async fn test_pull_retrieval_leg_url_carries_no_recipient_identity() {
    let relay = common::spawn_relay().await;
    let request = PullRequest::new("distinctive-recipient-id-should-not-appear-in-url");
    relay
        .store
        .stage_pull(request.recipient_id.clone(), request.rendezvous_token.clone())
        .await;

    let retrieval_url = format!("{}/v1/pulls/{}", relay.base_url, request.rendezvous_token);
    assert!(
        !retrieval_url.contains("distinctive-recipient-id-should-not-appear-in-url"),
        "the leg-2 retrieval URL must never contain the recipient identity"
    );

    let http = reqwest::Client::new();
    let response: serde_json::Value = http
        .get(&retrieval_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !response.to_string().contains("distinctive-recipient-id-should-not-appear-in-url"),
        "the leg-2 response body must not echo the recipient identity either"
    );
}
