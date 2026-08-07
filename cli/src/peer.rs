//! `parda-cli peer` — act as a real, long-running conversation partner
//! against a live relay.
//!
//! ## Why this exists
//!
//! The `demo` subcommand runs both sides of a conversation in one
//! process, which proves the protocol works but cannot serve as the
//! *other end* for a separate client. Testing the Android app therefore
//! needed either a second phone or nothing at all — so the mobile
//! send/receive path had never been exercised against a genuine second
//! party.
//!
//! This subcommand is that second party: it enrolls a real Signal
//! identity, publishes a real prekey bundle over HTTP to
//! `/v1/keys/{id}`, then polls `/v1/messages/{id}`, decrypts what
//! arrives, prints it, and (optionally) echoes a reply back. Everything
//! goes over the same REST surface the app uses.
//!
//! Unlike `demo`, the prekey bundle here **is** round-tripped through
//! the relay's JSON shape — it has to be, since the peer's whole purpose
//! is to be discoverable by a client that only ever sees that JSON. That
//! makes this the first thing in the workspace to exercise the
//! bundle-publish path end-to-end against a non-Rust client.
//!
//! ## Scope
//!
//! One conversation partner, no sealed sender, no mix routing — matching
//! what the Android client currently implements, because the point is to
//! be a counterpart for *it*. Identity is per-process and ephemeral:
//! restarting the peer generates a new identity and republishes, which
//! is correct for a test tool and is why it prints a warning saying so.

use std::time::Duration;

use libsignal_protocol::{IdentityKeyPair, PreKeyBundle, ProtocolAddress};
use parda_protocol::{
    envelope::MessageEnvelope,
    identity::LocalIdentity,
    session::SessionManager,
    store::InMemorySignalProtocolStore,
};

/// Base64 helpers matching the relay's `PreKeyBundleJson` encoding.
fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn d64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("bad base64: {e}"))
}

pub async fn run(relay_url: String, user_id: String, echo: bool) {
    let relay_url = relay_url.trim_end_matches('/').to_string();
    let http = reqwest::Client::new();

    println!("PARDA peer — acting as \"{user_id}\" against {relay_url}");
    println!(
        "note: this identity is generated fresh each run and is not persisted. \
         Restarting republishes a new key, which will break an already-established \
         session on the other side."
    );

    // ── Identity + bundle publish ────────────────────────────────────
    let identity = LocalIdentity::generate(rand::random::<u32>() % 0x3FFF + 1)
        .expect("generate identity");
    let mut store = InMemorySignalProtocolStore::new(identity.identity_key_pair, identity.registration_id);
    store.store_prekey_batch(&identity.one_time_prekeys).expect("store prekeys");
    store.store_signed_prekey_record(&identity.signed_prekey).expect("store signed prekey");

    let mut manager = SessionManager::new(
        ProtocolAddress::new(user_id.clone(), 1.into()),
        store,
    );

    let bundle_json = bundle_to_json(&identity);
    let resp = http
        .post(format!("{relay_url}/v1/keys/{user_id}"))
        .json(&bundle_json)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => println!("published prekey bundle ✓"),
        Ok(r) => {
            eprintln!("failed to publish prekey bundle: HTTP {}", r.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("could not reach relay at {relay_url}: {e}");
            std::process::exit(1);
        }
    }

    println!("polling for messages — start a chat with \"{user_id}\" from the app\n");

    // ── Poll / decrypt / optionally reply ────────────────────────────
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let Ok(resp) = http.get(format!("{relay_url}/v1/messages/{user_id}")).send().await else {
            continue;
        };
        let Ok(body) = resp.json::<serde_json::Value>().await else { continue };
        let Some(messages) = body.get("messages").and_then(|m| m.as_array()) else { continue };

        for raw in messages {
            // The relay flattens `StoredEnvelope`, so the envelope fields sit
            // beside `id` rather than under an `envelope` key — the same shape
            // the Android client parses.
            let envelope: MessageEnvelope = match serde_json::from_value(raw.clone()) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("skipping malformed envelope: {e}");
                    continue;
                }
            };
            let sender = envelope.sender_id.clone();

            match manager.decrypt(&envelope).await {
                Ok(plaintext) => {
                    let text = String::from_utf8_lossy(&plaintext);
                    println!("[{sender}] {text}");

                    if echo && !sender.is_empty() {
                        let reply = format!("echo: {text}");
                        if let Err(e) = send_reply(&http, &relay_url, &mut manager, &sender, &reply).await {
                            eprintln!("  reply failed: {e}");
                        } else {
                            println!("  → replied");
                        }
                    }
                }
                Err(e) => eprintln!("[{sender}] decrypt failed: {e}"),
            }
        }
    }
}

async fn send_reply(
    http: &reqwest::Client,
    relay_url: &str,
    manager: &mut SessionManager,
    recipient: &str,
    body: &str,
) -> Result<(), String> {
    let address = ProtocolAddress::new(recipient.to_string(), 1.into());
    let envelope = manager
        .encrypt(&address, body.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let resp = http
        .post(format!("{relay_url}/v1/messages/{recipient}"))
        .json(&envelope)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

/// Build the relay's `PreKeyBundleJson` shape from a [`LocalIdentity`].
fn bundle_to_json(identity: &LocalIdentity) -> serde_json::Value {
    let bundle: PreKeyBundle = identity.build_prekey_bundle().expect("build bundle");
    let identity_key = bundle.identity_key().expect("identity key");
    let signed_pre_key_public = bundle.signed_pre_key_public().expect("signed prekey public");
    let signed_pre_key_signature = bundle.signed_pre_key_signature().expect("signature");
    let signed_pre_key_id: u32 = bundle.signed_pre_key_id().expect("signed prekey id").into();

    let one_time_id: Option<u32> = bundle.pre_key_id().ok().flatten().map(Into::into);
    let one_time_public = bundle
        .pre_key_public()
        .ok()
        .flatten()
        .map(|k| b64(&k.serialize()));

    serde_json::json!({
        "registration_id": bundle.registration_id().expect("registration id"),
        "device_id": 1,
        "identity_key": b64(&identity_key.serialize()),
        "signed_prekey_id": signed_pre_key_id,
        "signed_prekey_public": b64(&signed_pre_key_public.serialize()),
        "signed_prekey_signature": b64(signed_pre_key_signature),
        "one_time_prekey_id": one_time_id,
        "one_time_prekey_public": one_time_public,
    })
}

/// Parse a relay `PreKeyBundleJson` back into a libsignal [`PreKeyBundle`].
/// Unused by the peer loop itself (the app initiates), but kept beside
/// [`bundle_to_json`] so both directions of the same wire shape live
/// together and cannot drift apart unnoticed.
#[allow(dead_code)]
pub fn bundle_from_json(v: &serde_json::Value) -> Result<PreKeyBundle, String> {
    use libsignal_protocol::{IdentityKey, PublicKey};

    let get_str = |k: &str| -> Result<String, String> {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("missing field {k}"))
    };
    let get_u32 = |k: &str| -> Result<u32, String> {
        v.get(k)
            .and_then(|x| x.as_u64())
            .map(|x| x as u32)
            .ok_or_else(|| format!("missing field {k}"))
    };

    let identity_key = IdentityKey::decode(&d64(&get_str("identity_key")?)?)
        .map_err(|e| e.to_string())?;
    let signed_public = PublicKey::deserialize(&d64(&get_str("signed_prekey_public")?)?)
        .map_err(|e| e.to_string())?;
    let one_time = match (
        v.get("one_time_prekey_id").and_then(|x| x.as_u64()),
        v.get("one_time_prekey_public").and_then(|x| x.as_str()),
    ) {
        (Some(id), Some(pk)) => Some((
            (id as u32).into(),
            PublicKey::deserialize(&d64(pk)?).map_err(|e| e.to_string())?,
        )),
        _ => None,
    };

    PreKeyBundle::new(
        get_u32("registration_id")?,
        1u32.into(),
        one_time,
        get_u32("signed_prekey_id")?.into(),
        signed_public,
        d64(&get_str("signed_prekey_signature")?)?,
        identity_key,
    )
    .map_err(|e| e.to_string())
}

/// Kept so the module's own identity type is referenced even when the
/// helper above is compiled out.
#[allow(dead_code)]
fn _assert_identity_type(_: &IdentityKeyPair) {}
