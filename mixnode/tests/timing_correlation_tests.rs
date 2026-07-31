//! Sub-Phase 2B timing-correlation statistical test — the deliverable
//! gate for this sub-phase (`docs/THREAT_MODEL.md` §3.6).
//!
//! ## Adversary model tested
//!
//! A GPA who observes exactly two things per message flow: when it
//! entered the mix network (the sender's POST to the first hop) and when
//! it exited (arrival at the relay's store). This is the standard
//! entry/exit timing-correlation model — it does **not** additionally
//! assume the adversary instruments every interior hop, which would be a
//! *stronger* adversary than this test exercises. Treat this test's
//! result as bounded to that model, not a claim about a fully
//! interior-instrumented adversary.
//!
//! ## Method
//!
//! Launch [`NUM_FLOWS`] concurrent (sender, recipient) flows, each
//! routed over an independently-chosen `PATH_LENGTH`-hop path through a
//! shared pool of real, running `parda-mixnode` daemons plus a real
//! ephemeral relay. Record each flow's true send time and observed
//! relay-arrival time.
//!
//! The statistic is **Spearman rank correlation between send order and
//! arrival order**, not raw-timestamp Pearson correlation. That
//! distinction matters: because arrival ≈ send + (a random, but
//! strictly non-negative, per-path delay), raw timestamps are
//! *trivially* positively correlated regardless of how good the mixing
//! is — a message can never arrive before it's sent, so any batch of
//! sends spread over a short window will, on average, still exit in a
//! roughly similar order purely from that additive structure. That's a
//! fact about how time works, not an anonymity leak. What actually
//! matters for anonymity is whether the *relative order* of exits still
//! reveals the relative order of entries — i.e., whether an adversary
//! who sees only the arrival-time ranking can recover the send-time
//! ranking. Spearman correlation on the ranks isolates exactly that.
//!
//! A null distribution is built by recomputing the same rank-correlation
//! statistic across [`NUM_PERMUTATIONS`] random re-pairings (a
//! permutation test — no assumption of normality, calibrated to this
//! exact sample size). If the true pairing's rank correlation isn't a
//! significant outlier against that null, an adversary watching only
//! entry/exit timestamps cannot use their ordering to recover which
//! send matches which arrival, above chance, at the tested scale.
//!
//! ## Honesty about scope
//!
//! This is an **empirical, statistical result bounded to the tested
//! scale** ([`NUM_FLOWS`] concurrent flows, [`PATH_LENGTH`]-hop paths,
//! [`AVG_HOP_DELAY_MS`] average per-hop delay) — not a formal,
//! asymptotic anonymity proof. A permutation test has an irreducible
//! false-failure rate equal to its significance threshold even when the
//! system genuinely provides no exploitable correlation; the threshold
//! here (`P_VALUE_THRESHOLD`) is chosen to keep that CI flakiness low
//! (~1%), not because 0.01 has some special cryptographic meaning.

mod common;

use std::time::{Duration, Instant};

use parda_protocol::{
    envelope::{EnvelopeType, MessageEnvelope},
    mixnet,
};
use rand::seq::SliceRandom;

const NUM_MIX_NODES: usize = 5;
const PATH_LENGTH: usize = 3;
const AVG_HOP_DELAY_MS: u64 = 250;
const NUM_FLOWS: usize = 8;
const SEND_STAGGER_MS: u64 = 1;
const NUM_PERMUTATIONS: usize = 5_000;
const P_VALUE_THRESHOLD: f64 = 0.005;

fn make_envelope(flow_index: usize) -> MessageEnvelope {
    MessageEnvelope {
        sender_id: format!("flow-sender-{flow_index}"),
        recipient_id: format!("flow-recipient-{flow_index}"),
        ciphertext: format!("opaque-ciphertext-for-flow-{flow_index}").into_bytes(),
        envelope_type: EnvelopeType::Ratchet,
        timestamp_ms: 1_753_900_000_000,
        version: 2,
        sealed_sender: false,
        routing_hint: None,
        self_destruct_at: None,
    }
}

/// Rank-transform (0-indexed, ascending) — ties aren't a concern here
/// since wall-clock timestamps are effectively continuous.
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

/// Permutation-test p-value on **Spearman rank correlation**: fraction
/// of random re-pairings whose |rank correlation| is at least as
/// extreme as the true pairing's. See module docs for why rank
/// correlation, not raw-timestamp correlation, is the right statistic.
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
async fn test_send_to_arrival_timing_does_not_leak_flow_pairing_above_chance() {
    let relay = common::spawn_relay().await;

    let mut nodes = Vec::with_capacity(NUM_MIX_NODES);
    for _ in 0..NUM_MIX_NODES {
        nodes.push(common::spawn_mixnode(&relay.base_url).await);
    }
    // Let listeners actually come up before hammering them.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let topology = mixnet::MixTopology::new(nodes);
    let http = reqwest::Client::new();

    // Start watching for every flow's arrival *before* sending anything,
    // so no arrival can race ahead of its poll task.
    let mut arrival_tasks = Vec::with_capacity(NUM_FLOWS);
    for i in 0..NUM_FLOWS {
        let store = relay.store.clone();
        arrival_tasks.push(tokio::spawn(async move {
            let envelopes = common::wait_for_delivery(
                &store,
                &format!("flow-recipient-{i}"),
                Duration::from_secs(10),
            )
            .await;
            assert_eq!(envelopes.len(), 1);
            Instant::now()
        }));
    }

    let base = Instant::now();
    let mut send_times = Vec::with_capacity(NUM_FLOWS);
    for i in 0..NUM_FLOWS {
        let envelope = make_envelope(i);
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        let path = topology.choose_path(PATH_LENGTH).unwrap();
        let packet_bytes = mixnet::build_packet(
            &envelope_bytes,
            &path,
            Duration::from_millis(AVG_HOP_DELAY_MS),
            mixnet::DEFAULT_MIX_PAYLOAD_SIZE,
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
            .expect("first hop must accept a well-formed packet");
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
        "send-time/arrival-time correlation for the true flow pairing (p = {p_value:.4}) is a \
         significant outlier against {NUM_PERMUTATIONS} random re-pairings — an adversary \
         watching only entry/exit timestamps could distinguish the real pairing from chance \
         at the tested scale ({NUM_FLOWS} flows, {PATH_LENGTH}-hop paths, \
         {AVG_HOP_DELAY_MS}ms avg per-hop delay)"
    );
}
