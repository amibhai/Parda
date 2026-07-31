//! SQLCipher-backed relay store — encrypted at rest.
//!
//! Replaces the Phase 1 in-memory `HashMap` store. Prekey bundles and
//! pending message envelopes are persisted to a single SQLCipher database
//! file, so a relay restart no longer loses queued messages (Phase 1 Known
//! Risk #2 in `docs/phase1-architecture.md` §10).
//!
//! ## Encryption at rest
//!
//! The database is opened with `PRAGMA key = <PARDA_DB_KEY>` before any
//! other statement runs, per SQLCipher's own required sequence. Without the
//! correct key, every subsequent query fails — SQLCipher does not degrade
//! to reading its own file as plaintext. See
//! `server/tests/persistence_tests.rs::test_wrong_key_cannot_read_database`
//! and `::test_database_file_is_not_plaintext_on_disk` for the tests that
//! back this claim.
//!
//! `PARDA_DB_KEY` has no default in [`RelayStore::new`] — an unset key is a
//! startup error, not a silent fallback to an unencrypted or
//! weakly-encrypted database. Tests that don't care about a specific key use
//! [`RelayStore::open_ephemeral`], which opens an in-memory database with a
//! fixed test-only key.
//!
//! ## Migrations
//!
//! Schema changes are tracked via `PRAGMA user_version` and applied by
//! [`run_migrations`] on every open. `CREATE TABLE IF NOT EXISTS` makes
//! migration 1 safe to run against a pre-existing database, and each
//! future migration must remain additive/idempotent in the same way — the
//! explicit requirement (Sub-Phase 2A cross-cutting requirement) is that
//! adopting this store must never require wiping prior data.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{params, Connection, OptionalExtension};

use parda_protocol::sealed_sender::CertificateAuthority;

use crate::models::{PreKeyBundleJson, StoredEnvelope};

/// Thread-safe handle to the relay store.
pub type SharedRelayStore = Arc<RelayStore>;

/// Upper bound on a requested sender-certificate lifetime, regardless of
/// what the client asks for in `IssueSenderCertRequest::ttl_secs`.
const MAX_SENDER_CERT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Fixed key used only by [`RelayStore::open_ephemeral`]. Never used for a
/// database file that's expected to persist real data.
const EPHEMERAL_TEST_KEY: &str = "parda-ephemeral-test-key-do-not-use-in-production";

pub struct RelayStore {
    conn: Arc<Mutex<Connection>>,
    /// Sender-certificate authority. Generated fresh at process startup —
    /// see `parda_protocol::sealed_sender` module docs for why this is a
    /// prototype-only posture (no offline/HSM-held trust root yet), and
    /// `docs/THREAT_MODEL.md` for the resulting trust boundary.
    ca: CertificateAuthority,
}

// ─── Construction ───────────────────────────────────────────────────────────

impl RelayStore {
    /// Open (or create) the relay's persistent, encrypted-at-rest store.
    ///
    /// Reads `PARDA_DB_PATH` (default `parda-relay.sqlite3`) and
    /// `PARDA_DB_KEY` (**required** — panics if unset, deliberately: an
    /// unencrypted or default-keyed relay store is not an acceptable silent
    /// fallback).
    pub fn new() -> SharedRelayStore {
        let path = std::env::var("PARDA_DB_PATH").unwrap_or_else(|_| "parda-relay.sqlite3".to_string());
        let key = std::env::var("PARDA_DB_KEY").unwrap_or_else(|_| {
            panic!(
                "PARDA_DB_KEY is not set. The relay store is encrypted at rest and refuses to \
                 start with a default or empty key. Set PARDA_DB_KEY to a strong passphrase \
                 (e.g. `openssl rand -hex 32`)."
            )
        });
        Self::open(path, &key)
    }

    /// Open a specific database file with an explicit key. Used by `new()`
    /// and directly by persistence tests that need to reopen the same file
    /// across simulated "restarts".
    pub fn open(path: impl AsRef<Path>, key: &str) -> SharedRelayStore {
        let conn = Connection::open(path).expect("failed to open relay database file");
        Self::from_connection(conn, key)
    }

    /// Open an in-memory, ephemeral store for tests. Not persistent by
    /// design — nothing survives process exit, and the fixed key means this
    /// must never be pointed at a real database file.
    pub fn open_ephemeral() -> SharedRelayStore {
        let conn = Connection::open_in_memory().expect("failed to open in-memory relay database");
        Self::from_connection(conn, EPHEMERAL_TEST_KEY)
    }

    fn from_connection(conn: Connection, key: &str) -> SharedRelayStore {
        // Must be the first statement executed on this connection — SQLCipher
        // requires PRAGMA key before any other query, including migrations.
        conn.pragma_update(None, "key", key)
            .expect("failed to set SQLCipher key");

        // Touching the database now forces SQLCipher to actually attempt a
        // page read/decrypt. An empty/new file always succeeds here
        // regardless of key (there's nothing to decrypt yet); an existing
        // file opened with the wrong key fails at this point rather than
        // later, mid-request.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect(
            "failed to unlock relay database — wrong PARDA_DB_KEY, or the file is not a \
             SQLCipher database",
        );

        run_migrations(&conn).expect("failed to run relay database migrations");

        let ca = CertificateAuthority::new().expect("failed to initialise sealed-sender certificate authority");

        Arc::new(Self {
            conn: Arc::new(Mutex::new(conn)),
            ca,
        })
    }

    fn conn_handle(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }
}

/// Applies schema migrations up to [`CURRENT_SCHEMA_VERSION`], tracked via
/// `PRAGMA user_version`. Idempotent: running it against an already
/// up-to-date database is a no-op.
const CURRENT_SCHEMA_VERSION: i64 = 1;

fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if current < 1 {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS prekey_bundles (
                user_id     TEXT PRIMARY KEY,
                bundle_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id            TEXT PRIMARY KEY,
                recipient_id  TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
            ",
        )?;
    }

    if current < CURRENT_SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    }

    Ok(())
}

// ─── Sealed-sender certificate authority ────────────────────────────────────

impl RelayStore {
    /// Base64-ready trust root public key clients pin to validate
    /// sealed-sender certificates.
    pub fn trust_root_public_key(&self) -> parda_protocol::PublicKey {
        self.ca.trust_root_public_key()
    }

    /// Issue a sender certificate for `user_id`'s identity key. `ttl_secs`
    /// is clamped to `MAX_SENDER_CERT_TTL`.
    pub fn issue_sender_certificate(
        &self,
        user_id: String,
        identity_key: parda_protocol::PublicKey,
        device_id: parda_protocol::DeviceId,
        ttl_secs: u64,
    ) -> parda_protocol::error::Result<parda_protocol::SenderCertificate> {
        let ttl = Duration::from_secs(ttl_secs).min(MAX_SENDER_CERT_TTL);
        self.ca
            .issue_sender_certificate(user_id, identity_key, device_id, ttl)
    }
}

// ─── Prekey bundle + message operations ─────────────────────────────────────
//
// Each operation runs the actual (synchronous) SQLite call inside
// `spawn_blocking` so a slow disk/lock never stalls the async executor.

impl RelayStore {
    /// Store (or replace) the prekey bundle for `user_id`.
    pub async fn put_bundle(&self, user_id: String, bundle: PreKeyBundleJson) {
        let conn = self.conn_handle();
        tokio::task::spawn_blocking(move || {
            let json = serde_json::to_string(&bundle).expect("PreKeyBundleJson must serialise");
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO prekey_bundles (user_id, bundle_json) VALUES (?1, ?2)
                 ON CONFLICT(user_id) DO UPDATE SET bundle_json = excluded.bundle_json",
                params![user_id, json],
            )
            .expect("failed to store prekey bundle");
        })
        .await
        .expect("blocking task panicked");
    }

    /// Retrieve the prekey bundle for `user_id`, if present.
    pub async fn get_bundle(&self, user_id: &str) -> Option<PreKeyBundleJson> {
        let conn = self.conn_handle();
        let user_id = user_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let json: Option<String> = conn
                .query_row(
                    "SELECT bundle_json FROM prekey_bundles WHERE user_id = ?1",
                    params![user_id],
                    |row| row.get(0),
                )
                .optional()
                .expect("failed to query prekey bundle");
            json.map(|j| serde_json::from_str(&j).expect("stored bundle_json must deserialise"))
        })
        .await
        .expect("blocking task panicked")
    }

    /// Enqueue an envelope for delivery to `recipient_id`.
    pub async fn enqueue(&self, recipient_id: String, envelope: StoredEnvelope) {
        let conn = self.conn_handle();
        tokio::task::spawn_blocking(move || {
            let json = serde_json::to_string(&envelope).expect("StoredEnvelope must serialise");
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO messages (id, recipient_id, envelope_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![envelope.id, recipient_id, json, envelope.envelope.timestamp_ms as i64],
            )
            .expect("failed to enqueue message");
        })
        .await
        .expect("blocking task panicked");
    }

    /// Drain all pending envelopes for `user_id` (fetch-and-clear), ordered
    /// by arrival.
    pub async fn drain(&self, user_id: &str) -> Vec<StoredEnvelope> {
        let conn = self.conn_handle();
        let user_id = user_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT envelope_json FROM messages WHERE recipient_id = ?1
                     ORDER BY created_at_ms ASC",
                )
                .expect("failed to prepare drain query");
            let envelopes: Vec<StoredEnvelope> = stmt
                .query_map(params![user_id], |row| row.get::<_, String>(0))
                .expect("failed to run drain query")
                .map(|json| {
                    serde_json::from_str(&json.expect("row must yield envelope_json"))
                        .expect("stored envelope_json must deserialise")
                })
                .collect();
            conn.execute("DELETE FROM messages WHERE recipient_id = ?1", params![user_id])
                .expect("failed to clear drained messages");
            envelopes
        })
        .await
        .expect("blocking task panicked")
    }

    /// Delete a single envelope by ID for `user_id`.
    pub async fn delete_message(&self, user_id: &str, message_id: &str) -> bool {
        let conn = self.conn_handle();
        let user_id = user_id.to_string();
        let message_id = message_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let affected = conn
                .execute(
                    "DELETE FROM messages WHERE id = ?1 AND recipient_id = ?2",
                    params![message_id, user_id],
                )
                .expect("failed to delete message");
            affected > 0
        })
        .await
        .expect("blocking task panicked")
    }
}
