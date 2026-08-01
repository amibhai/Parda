//! Client-side encrypted local message store (SQLCipher) — Sub-Phase 3D.
//!
//! ## Build note: the Perl gap, and how it got resolved
//!
//! This crate uses the same vendored-SQLCipher approach
//! `server/src/store.rs` already proved out (`rusqlite`'s
//! `bundled-sqlcipher-vendored-openssl` feature), which needs a complete
//! Perl for OpenSSL's `Configure` step. This was initially written
//! against a dev environment whose only Perl (Git-for-Windows/MSYS) was
//! missing `Locale::Maketext::Simple` — the exact gap
//! `docs/phase1-architecture.md` §11 already documented — so the crate
//! could not be compiled at first. Fixed for that session by installing
//! a portable Strawberry Perl and putting it first on `PATH`; once done,
//! this crate (and `parda-relay`, `parda-mixnode`'s dev-dependency on it,
//! and `parda-cli`) all built and passed their full test suites with
//! zero errors on the first successful compile — no logic bugs were
//! found in this crate specifically. All 7 tests in
//! `tests/client_store_tests.rs` pass. See
//! `docs/phase3-3a-self-destruct-design.md` §12 for the full account,
//! including why this is recorded rather than silently fixed: a
//! from-scratch, first-try clean compile is worth noting precisely
//! *because* this project's standard is not to claim correctness without
//! a test that actually ran — this is that record.
//!
//! ## The structural boundary this module exists to enforce
//!
//! Per the brief: "anything flagged `self_destruct_at` or read-triggered
//! must never be written to this store in the first place; persistence
//! and destructibility are mutually exclusive per-message, and the
//! store's write path must enforce that, not just the UI layer."
//!
//! [`LocalMessageStore::store_message`] checks
//! `envelope.self_destruct_at.is_some() || envelope.read_triggered_destruct`
//! and returns [`StoreError::RefusesSelfDestructingMessage`] — never
//! silently drops the flag and persists anyway — before any SQL runs.
//! There is no second code path into the `messages` table; every write
//! goes through this one function. See
//! `tests/client_store_tests.rs::test_self_destructing_messages_are_refused_time_bound`
//! and `::test_self_destructing_messages_are_refused_read_triggered`.
//!
//! This enforcement is necessarily **advisory-input-dependent** in one
//! sense worth being precise about: it trusts the caller's own local
//! `MessageEnvelope` value (typically one this device itself just
//! decrypted), not a value that traveled untrusted over the network
//! post-decryption. That's an appropriate trust boundary — a message a
//! device has already decrypted and is choosing to persist is squarely
//! that device's own decision — but it's a different trust boundary than
//! e.g. `MixTransport`'s, and conflating the two would be the same kind
//! of "advisory vs. enforced" confusion `envelope.rs`'s own module docs
//! already warn about for `self_destruct_at` on the wire.
//!
//! ## Sub-Phase 4.5E: the holding area, and why it does not weaken the
//! boundary above
//!
//! Sub-Phase 4.5E adds [`LocalMessageStore::stage_self_destructing`] and
//! a `pending_self_destruct` table, so a pending self-destructing
//! message survives a process restart instead of silently vanishing (or,
//! worse, outliving its deadline unnoticed). Read as a summary, "the
//! store now persists self-destructing messages" would sound like the
//! refusal above was quietly relaxed. It was not, and the shape of the
//! change is what guarantees that:
//!
//! - **Different table, different type.** The holding area stores a
//!   `parda_protocol::self_destruct::PersistedSelfDestructState` (AEAD
//!   ciphertext + derived key + mode + deadline), never a
//!   `MessageEnvelope`. `store_message`'s refusal is untouched — there
//!   is still no way to get a self-destructing envelope into `messages`.
//! - **Rows are deleted, never marked.** Reading one
//!   ([`LocalMessageStore::take_self_destructing`]) deletes it in the
//!   same transaction; expired rows are deleted by
//!   [`LocalMessageStore::purge_expired_self_destructing`]. Nothing here
//!   accumulates as history.
//! - **It is a real, documented trade-off, not a free win.** The derived
//!   key now touches disk (SQLCipher-encrypted, same trust boundary as
//!   everything else here, never weaker) where Sub-Phase 3A's primitive
//!   kept it memory-only. That cost is stated in full on
//!   `PersistedSelfDestructState`, in `docs/THREAT_MODEL.md`, and in the
//!   README — and staging is opt-in per message, never automatic.

pub mod error;

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use parda_protocol::{
    envelope::MessageEnvelope,
    self_destruct::{DestructMode, PersistedSelfDestructState},
};
use rusqlite::{params, Connection};

pub use error::StoreError;

pub type SharedLocalMessageStore = Arc<LocalMessageStore>;

/// Fixed key used only by [`LocalMessageStore::open_ephemeral`]. Never
/// used for a database file expected to persist real data — mirrors
/// `server/src/store.rs`'s identical convention.
const EPHEMERAL_TEST_KEY: &str = "parda-client-store-ephemeral-test-key-do-not-use-in-production";

const CURRENT_SCHEMA_VERSION: i64 = 2;

pub struct LocalMessageStore {
    conn: Mutex<Connection>,
}

/// One row of persisted message history.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub peer_address: String,
    pub direction: MessageDirection,
    pub envelope: MessageEnvelope,
    pub stored_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDirection {
    Sent,
    Received,
}

impl MessageDirection {
    fn as_str(self) -> &'static str {
        match self {
            MessageDirection::Sent => "sent",
            MessageDirection::Received => "received",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "sent" => Some(Self::Sent),
            "received" => Some(Self::Received),
            _ => None,
        }
    }
}

impl LocalMessageStore {
    /// Open (or create) the store at `path`, encrypted with `key`.
    /// Mirrors `server::store::RelayStore::open`'s SQLCipher sequencing
    /// exactly (`PRAGMA key` must be the first statement executed — see
    /// that module's docs for why) — deliberately not re-deriving that
    /// logic differently here.
    pub fn open(path: impl AsRef<std::path::Path>, key: &str) -> Result<SharedLocalMessageStore, StoreError> {
        let conn = Connection::open(path).map_err(|e| StoreError::Sqlite(e.to_string()))?;
        Self::from_connection(conn, key)
    }

    /// In-memory, ephemeral store for tests — nothing survives process
    /// exit, fixed test-only key.
    pub fn open_ephemeral() -> Result<SharedLocalMessageStore, StoreError> {
        let conn = Connection::open_in_memory().map_err(|e| StoreError::Sqlite(e.to_string()))?;
        Self::from_connection(conn, EPHEMERAL_TEST_KEY)
    }

    fn from_connection(conn: Connection, key: &str) -> Result<SharedLocalMessageStore, StoreError> {
        conn.pragma_update(None, "key", key)
            .map_err(|e| StoreError::Sqlite(format!("failed to set SQLCipher key: {e}")))?;

        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
            .map_err(|e| {
                StoreError::Sqlite(format!(
                    "failed to unlock client store — wrong key, or not a SQLCipher database: {e}"
                ))
            })?;

        run_migrations(&conn)?;

        Ok(Arc::new(Self { conn: Mutex::new(conn) }))
    }

    /// Persist `envelope` (exchanged with `peer_address`, in `direction`)
    /// to durable, encrypted-at-rest history.
    ///
    /// **Refuses** — does not persist, does not silently strip the flag
    /// — any self-destructing envelope. See module docs.
    pub async fn store_message(
        &self,
        peer_address: &str,
        direction: MessageDirection,
        envelope: &MessageEnvelope,
    ) -> Result<String, StoreError> {
        if envelope.self_destruct_at.is_some() || envelope.read_triggered_destruct {
            return Err(StoreError::RefusesSelfDestructingMessage);
        }

        let id = local_row_id();
        let envelope_json =
            serde_json::to_string(envelope).map_err(|e| StoreError::Codec(e.to_string()))?;
        let stored_at_ms = envelope.timestamp_ms;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO messages (id, peer_address, direction, envelope_json, stored_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, peer_address, direction.as_str(), envelope_json, stored_at_ms as i64],
        )
        .map_err(|e| StoreError::Sqlite(e.to_string()))?;

        Ok(id)
    }

    /// All persisted history with `peer_address`, oldest first.
    pub async fn history_for(&self, peer_address: &str) -> Result<Vec<StoredMessage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, peer_address, direction, envelope_json, stored_at_ms
                 FROM messages WHERE peer_address = ?1 ORDER BY stored_at_ms ASC",
            )
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;

        let rows = stmt
            .query_map(params![peer_address], |row| {
                let id: String = row.get(0)?;
                let peer_address: String = row.get(1)?;
                let direction: String = row.get(2)?;
                let envelope_json: String = row.get(3)?;
                let stored_at_ms: i64 = row.get(4)?;
                Ok((id, peer_address, direction, envelope_json, stored_at_ms))
            })
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;

        let mut out = Vec::new();
        for row in rows {
            let (id, peer_address, direction, envelope_json, stored_at_ms) =
                row.map_err(|e| StoreError::Sqlite(e.to_string()))?;
            let envelope: MessageEnvelope =
                serde_json::from_str(&envelope_json).map_err(|e| StoreError::Codec(e.to_string()))?;
            let direction = MessageDirection::from_str(&direction)
                .ok_or_else(|| StoreError::Codec(format!("corrupt direction column: {direction:?}")))?;
            out.push(StoredMessage {
                id,
                peer_address,
                direction,
                envelope,
                stored_at_ms: stored_at_ms as u64,
            });
        }
        Ok(out)
    }

    /// Delete all persisted history with `peer_address`. Intended to be
    /// called alongside
    /// `parda_protocol::session::SessionManager::burn_conversation`
    /// (Sub-Phase 3D's other deliverable) so "burn this conversation"
    /// clears *both* the live session state and any persisted history —
    /// the two are separate calls (session-burn lives in `parda-protocol`,
    /// which has no SQLCipher dependency and shouldn't gain one just for
    /// this), not one hidden combined operation, but a caller wiring up
    /// "burn" should call both.
    pub async fn delete_history_for(&self, peer_address: &str) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute("DELETE FROM messages WHERE peer_address = ?1", params![peer_address])
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        Ok(affected)
    }

    /// Total row count — test/diagnostic convenience.
    pub async fn total_message_count(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
            .map_err(|e| StoreError::Sqlite(e.to_string()))
    }

    // ── Self-destruct holding area (Sub-Phase 4.5E) ─────────────────────
    //
    // See `parda_protocol::self_destruct::PersistedSelfDestructState`'s
    // docs for the trade-off staging a message here accepts (the derived
    // key touches disk, SQLCipher-encrypted, instead of never being
    // persisted at all) and why it is opt-in per message.

    /// Stage an already-sealed self-destructing message so it survives a
    /// process restart. Returns the holding-area row ID.
    ///
    /// This does **not** relax [`Self::store_message`]'s refusal of
    /// self-destructing envelopes — that boundary is untouched, and this
    /// writes to an entirely different table. See `run_migrations`.
    pub async fn stage_self_destructing(
        &self,
        peer_address: &str,
        state: &PersistedSelfDestructState,
        staged_at_ms: u64,
    ) -> Result<String, StoreError> {
        let id = local_row_id();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pending_self_destruct
               (id, peer_address, ciphertext, key_bytes, mode, expires_at_ms, staged_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                peer_address,
                state.ciphertext(),
                state.key_bytes().as_slice(),
                mode_to_str(state.mode()),
                state.expires_at_ms().map(|ms| ms as i64),
                staged_at_ms as i64,
            ],
        )
        .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        Ok(id)
    }

    /// Read a staged message back **and delete its row in the same
    /// transaction** — fetch-and-clear, never read-and-leave.
    ///
    /// The delete is unconditional and happens even though the caller may
    /// still fail to [`parda_protocol::self_destruct::SelfDestructingMessage::restore`]
    /// it (expired deadline, detected clock rollback). That is deliberate
    /// and is the fail-closed direction: a row that cannot be restored
    /// must not be left on disk for a later attempt under a more
    /// favourable clock. Matches the "never a lingering record"
    /// discipline this store already applies on its refusal path.
    pub async fn take_self_destructing(
        &self,
        id: &str,
    ) -> Result<Option<PersistedSelfDestructState>, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;

        let row = tx
            .query_row(
                "SELECT ciphertext, key_bytes, mode, expires_at_ms
                 FROM pending_self_destruct WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .ok();

        let Some((ciphertext, key_vec, mode_str, expires_at_ms)) = row else {
            return Ok(None);
        };

        tx.execute("DELETE FROM pending_self_destruct WHERE id = ?1", params![id])
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        tx.commit().map_err(|e| StoreError::Sqlite(e.to_string()))?;

        let mode = mode_from_str(&mode_str)
            .ok_or_else(|| StoreError::Codec(format!("corrupt mode column: {mode_str:?}")))?;
        let key_bytes: [u8; 32] = key_vec.as_slice().try_into().map_err(|_| {
            StoreError::Codec(format!(
                "corrupt key_bytes column: expected 32 bytes, got {}",
                key_vec.len()
            ))
        })?;

        Ok(Some(PersistedSelfDestructState::from_parts(
            ciphertext,
            key_bytes,
            mode,
            expires_at_ms.map(|ms| ms as u64),
        )))
    }

    /// Delete every staged row whose deadline has passed as of `now_ms`.
    ///
    /// Rows with a `NULL` deadline (pure read-triggered — no deadline by
    /// design) are never swept: they are erased on read, and sweeping
    /// them on a timer would silently convert them into a different mode
    /// than the sender chose.
    ///
    /// Callers should run this at startup, *before* restoring anything,
    /// so a message that expired during downtime is deleted rather than
    /// merely refused on each attempt.
    pub async fn purge_expired_self_destructing(&self, now_ms: u64) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_self_destruct
             WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?1",
            params![now_ms as i64],
        )
        .map_err(|e| StoreError::Sqlite(e.to_string()))
    }

    /// IDs of every currently-staged message for `peer_address`, oldest
    /// first. Deliberately returns IDs rather than the states themselves:
    /// reading a state is a fetch-and-clear operation
    /// ([`Self::take_self_destructing`]), so a bulk "list with contents"
    /// call would either have to consume everything it listed or leave
    /// keys in memory the caller never asked for.
    pub async fn pending_self_destruct_ids(
        &self,
        peer_address: &str,
    ) -> Result<Vec<String>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id FROM pending_self_destruct
                 WHERE peer_address = ?1 ORDER BY staged_at_ms ASC",
            )
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params![peer_address], |row| row.get::<_, String>(0))
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| StoreError::Sqlite(e.to_string()))?);
        }
        Ok(out)
    }

    /// Staged-row count — test/diagnostic convenience.
    pub async fn pending_self_destruct_count(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT count(*) FROM pending_self_destruct", [], |row| row.get(0))
            .map_err(|e| StoreError::Sqlite(e.to_string()))
    }
}

fn run_migrations(conn: &Connection) -> Result<(), StoreError> {
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| StoreError::Sqlite(e.to_string()))?;

    if current < 1 {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS messages (
                id            TEXT PRIMARY KEY,
                peer_address  TEXT NOT NULL,
                direction     TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                stored_at_ms  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_address);
            ",
        )
        .map_err(|e| StoreError::Sqlite(e.to_string()))?;
    }

    // ── v2 (Sub-Phase 4.5E): the self-destruct holding area ──────────────
    //
    // Deliberately a *separate table* from `messages`, not a flag on it.
    // `messages` is durable history and its write path refuses
    // self-destructing envelopes outright (see module docs) — that
    // refusal is a load-bearing structural boundary and must not become
    // "refuses, unless a column says otherwise." A row here is
    // short-lived pending state that gets DELETEd, never history.
    if current < 2 {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS pending_self_destruct (
                id            TEXT PRIMARY KEY,
                peer_address  TEXT NOT NULL,
                ciphertext    BLOB NOT NULL,
                key_bytes     BLOB NOT NULL,
                mode          TEXT NOT NULL,
                expires_at_ms INTEGER,
                staged_at_ms  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_sd_peer ON pending_self_destruct(peer_address);
            CREATE INDEX IF NOT EXISTS idx_pending_sd_expiry ON pending_self_destruct(expires_at_ms);
            ",
        )
        .map_err(|e| StoreError::Sqlite(e.to_string()))?;
    }

    if current < CURRENT_SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
    }
    Ok(())
}

fn mode_to_str(mode: DestructMode) -> &'static str {
    match mode {
        DestructMode::TimeBound => "time_bound",
        DestructMode::ReadTriggered => "read_triggered",
        DestructMode::Combined => "combined",
    }
}

fn mode_from_str(s: &str) -> Option<DestructMode> {
    match s {
        "time_bound" => Some(DestructMode::TimeBound),
        "read_triggered" => Some(DestructMode::ReadTriggered),
        "combined" => Some(DestructMode::Combined),
        _ => None,
    }
}

/// A dependency-free local primary key: nanosecond timestamp plus a
/// process-local monotonic counter. Never sent over the network or
/// trusted as unpredictable — only used as a local SQLite primary key,
/// so no need for the `uuid`/`rand` crates just for this.
fn local_row_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{seq:x}")
}
