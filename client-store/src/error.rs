//! Error type for `parda-client-store`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    /// The write path's core guarantee: a self-destructing envelope
    /// (time-bound or read-triggered) was rejected rather than
    /// persisted. See `lib.rs` module docs "The structural boundary
    /// this module exists to enforce."
    #[error(
        "refused to persist a self-destructing message — persistence and destructibility are \
         mutually exclusive per-message"
    )]
    RefusesSelfDestructingMessage,

    #[error("SQLCipher/SQLite error: {0}")]
    Sqlite(String),

    #[error("envelope codec error: {0}")]
    Codec(String),
}
