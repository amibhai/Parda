//! `parda-cli` — Sub-Phase 3D CLI prototype.
//!
//! Exercises, in one real end-to-end run: X3DH session establishment,
//! Double-Ratchet encrypt/decrypt, **real HTTP transport**
//! (`parda_protocol::transport::DirectTransport`, a genuine POST/GET
//! round trip — see `stub_relay` module docs for what's real and what's
//! a demo convenience), time-bound *or* read-triggered self-destruct,
//! the client-side encrypted history store's write-path exclusion of
//! self-destructing messages, and session-burn.
//!
//! ## Verified: this demo actually runs, all three modes
//!
//! Once the Perl gap (`client-store/src/lib.rs` module docs) was
//! resolved, this binary was run for real — `demo`, `demo --expire-secs
//! 1`, `demo --read-once`, and the mutually-exclusive-flags rejection —
//! all four exit 0 (the rejection case exits 2, as designed) with output
//! matching the documented guarantees exactly. Running it is also what
//! caught a real, pre-existing bug: see `protocol/src/transport.rs`'s
//! `FetchMessagesResponse` doc comment for what `DirectTransport::receive`
//! was doing wrong from Phase 1 until this demo's first real run against
//! a live relay hit it immediately. That's the brief's stated reason for
//! building this prototype early, borne out in practice, not just in
//! theory.
//!
//! ## Scope decision: prekey bundle exchange is in-process, not over HTTP
//!
//! The demo builds Bob's session directly from his `PreKeyBundle` object
//! rather than round-tripping it through the stub relay's `/v1/keys`
//! JSON shape first. This mirrors existing precedent in this workspace
//! (`server/tests/sealed_sender_relay_tests.rs`'s identical comment) and
//! keeps this prototype's own hand-written glue code smaller — the
//! bundle-upload/fetch JSON shape is already exercised by
//! `server/tests/`. What *is* real here, and is the point of this
//! prototype per the brief, is message send/receive over genuine HTTP
//! via `DirectTransport`.

mod peer;
mod stub_relay;

use std::time::Duration;

use clap::{Parser, Subcommand};
use libsignal_protocol::{IdentityKeyPair, ProtocolAddress};
use parda_client_store::{LocalMessageStore, MessageDirection};
use parda_protocol::{
    self_destruct::SelfDestructingMessage,
    session::SessionManager,
    store::InMemorySignalProtocolStore,
    transport::{DirectTransport, TransportLayer},
};

#[derive(Parser)]
#[command(name = "parda-cli", about = "PARDA CLI prototype (Sub-Phase 3D)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the full end-to-end demo described in this crate's module docs.
    Demo {
        /// Point at a real running parda-relay instead of the built-in
        /// stub. See `stub_relay` module docs.
        #[arg(long)]
        relay_url: Option<String>,
        /// Time-bound self-destruct: expire this many seconds after
        /// delivery. Mutually exclusive with `--read-once`.
        #[arg(long)]
        expire_secs: Option<u64>,
        /// Read-triggered self-destruct: gone after the demo's one
        /// simulated read. Mutually exclusive with `--expire-secs`.
        #[arg(long)]
        read_once: bool,
    },

    /// Act as a live conversation partner against a running relay, so a
    /// separate client (e.g. the Android app) has a real second party to
    /// talk to. See `peer` module docs.
    Peer {
        /// Base URL of the running parda-relay.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay_url: String,
        /// The user ID this peer registers as.
        #[arg(long, default_value = "bob")]
        user_id: String,
        /// Automatically reply to every message received.
        #[arg(long)]
        echo: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("parda_cli=info").init();

    let cli = Cli::parse();
    match cli.command {
        Command::Demo { relay_url, expire_secs, read_once } => {
            if expire_secs.is_some() && read_once {
                eprintln!("--expire-secs and --read-once are mutually exclusive — see design note §5b on why the two modes' guarantees must not blur together");
                std::process::exit(2);
            }
            run_demo(relay_url, expire_secs, read_once).await;
        }
        Command::Peer { relay_url, user_id, echo } => {
            peer::run(relay_url, user_id, echo).await;
        }
    }
}

async fn run_demo(relay_url: Option<String>, expire_secs: Option<u64>, read_once: bool) {
    let relay_base_url = match relay_url {
        Some(url) => url,
        None => {
            let url = stub_relay::spawn().await;
            println!("[demo] no --relay-url given — using the built-in stub relay at {url}");
            url
        }
    };

    // ── Identities ───────────────────────────────────────────────────
    let alice_identity =
        parda_protocol::identity::LocalIdentity::generate(1).expect("generate alice identity");
    let bob_identity =
        parda_protocol::identity::LocalIdentity::generate(2).expect("generate bob identity");

    let alice_addr = ProtocolAddress::new("alice".to_string(), 1.into());
    let bob_addr = ProtocolAddress::new("bob".to_string(), 1.into());

    let alice_ikp: IdentityKeyPair = alice_identity.identity_key_pair;
    let mut alice_store = InMemorySignalProtocolStore::new(alice_ikp, alice_identity.registration_id);
    alice_store.store_prekey_batch(&alice_identity.one_time_prekeys).unwrap();
    alice_store.store_signed_prekey_record(&alice_identity.signed_prekey).unwrap();
    let mut alice = SessionManager::new(alice_addr.clone(), alice_store);

    let mut bob_store =
        InMemorySignalProtocolStore::new(bob_identity.identity_key_pair, bob_identity.registration_id);
    bob_store.store_prekey_batch(&bob_identity.one_time_prekeys).unwrap();
    bob_store.store_signed_prekey_record(&bob_identity.signed_prekey).unwrap();
    let mut bob = SessionManager::new(bob_addr.clone(), bob_store);

    // Scope decision: in-process bundle hand-off — see module docs.
    let bob_bundle = bob_identity.build_prekey_bundle().expect("build bob's prekey bundle");
    alice.initiate_session(&bob_addr, &bob_bundle).await.expect("X3DH session initiation");
    println!("[demo] Alice established an X3DH session with Bob");

    // ── Real HTTP transport ─────────────────────────────────────────
    let alice_transport = DirectTransport::new(relay_base_url.clone());
    let bob_transport = DirectTransport::new(relay_base_url.clone());

    let plaintext = b"the field report is in the usual place";
    let mut envelope = alice.encrypt(&bob_addr, plaintext).await.expect("encrypt");

    if let Some(secs) = expire_secs {
        envelope = envelope.with_self_destruct(Duration::from_secs(secs));
        println!("[demo] message marked time-bound self-destruct: expires {secs}s after delivery");
    } else if read_once {
        envelope = envelope.with_read_triggered_destruct();
        println!("[demo] message marked read-triggered self-destruct: gone after first read");
    }

    alice_transport.send(&envelope).await.expect("send over real HTTP transport");
    println!("[demo] Alice sent the envelope over real HTTP to {relay_base_url}");

    let received = bob_transport.receive("bob").await.expect("receive over real HTTP transport");
    assert_eq!(received.len(), 1, "demo expects exactly one pending envelope");
    let received_envelope = received.into_iter().next().unwrap();
    println!("[demo] Bob fetched the envelope over real HTTP");

    let decrypted = bob.decrypt(&received_envelope).await.expect("decrypt");
    println!(
        "[demo] Bob decrypted: {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    // ── Self-destruct, history store, or both demonstrated ──────────
    if received_envelope.self_destruct_at.is_some() {
        let window = Duration::from_secs(expire_secs.unwrap_or(300));
        let sd = SelfDestructingMessage::seal(&decrypted, received_envelope.timestamp_ms, window)
            .expect("seal time-bound");
        println!("[demo] wrapped in a time-bound SelfDestructingMessage — will expire in {window:?}");
        let first_read = sd.open().unwrap();
        println!("[demo] read once now: {:?}", String::from_utf8_lossy(&first_read[..]));
        drop(first_read);
        println!("[demo] waiting past expiry to demonstrate erasure...");
        tokio::time::sleep(window + Duration::from_millis(200)).await;
        println!("[demo] is_expired() = {}, open() = {:?}", sd.is_expired(), sd.open().err());
    } else if received_envelope.read_triggered_destruct {
        let sd = SelfDestructingMessage::seal_read_triggered(&decrypted, received_envelope.timestamp_ms)
            .expect("seal read-triggered");
        println!("[demo] wrapped in a read-triggered SelfDestructingMessage");
        let first_read = sd.open().unwrap();
        println!("[demo] first read: {:?}", String::from_utf8_lossy(&first_read[..]));
        drop(first_read);
        println!("[demo] second read attempt: {:?} (must fail — see design note §5b)", sd.open().err());
    } else {
        let store = LocalMessageStore::open_ephemeral().expect("open client store");
        store
            .store_message("alice", MessageDirection::Received, &received_envelope)
            .await
            .expect("persist non-self-destructing message");
        let history = store.history_for("alice").await.unwrap();
        println!("[demo] persisted to the encrypted local store — {} message(s) in history", history.len());
    }

    // ── Session-burn ─────────────────────────────────────────────────
    let burned = bob.burn_conversation(&alice_addr);
    println!(
        "[demo] burned Bob's conversation with Alice — session_removed={}, identity_trust_removed={}",
        burned.session_removed, burned.identity_trust_removed
    );
    assert!(!bob.store.has_conversation_state(&alice_addr));
    println!("[demo] confirmed: no conversation state remains for Alice on Bob's side");

    println!("[demo] done.");
}
