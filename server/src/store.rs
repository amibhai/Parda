//! In-memory relay store.
//!
//! Stores prekey bundles and pending message envelopes entirely in RAM.
//! All data is lost on process exit — this is intentional for Phase 1.
//!
//! Phase 2 replacement: swap `RelayStore` for a PostgreSQL-backed store
//! implementing the same interface. No route handler needs to change.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::RwLock;

use crate::models::{PreKeyBundleJson, StoredEnvelope};

/// Thread-safe handle to the relay store.
pub type SharedRelayStore = Arc<RelayStore>;

pub struct RelayStore {
    /// Prekey bundles by user_id.
    bundles: RwLock<HashMap<String, PreKeyBundleJson>>,
    /// Pending message queues by recipient user_id.
    queues: RwLock<HashMap<String, VecDeque<StoredEnvelope>>>,
}

impl RelayStore {
    pub fn new() -> SharedRelayStore {
        Arc::new(Self {
            bundles: RwLock::new(HashMap::new()),
            queues: RwLock::new(HashMap::new()),
        })
    }

    // ── Prekey bundle operations ──────────────────────────────────────────

    /// Store (or replace) the prekey bundle for `user_id`.
    pub async fn put_bundle(&self, user_id: String, bundle: PreKeyBundleJson) {
        self.bundles.write().await.insert(user_id, bundle);
    }

    /// Retrieve the prekey bundle for `user_id`, if present.
    pub async fn get_bundle(&self, user_id: &str) -> Option<PreKeyBundleJson> {
        self.bundles.read().await.get(user_id).cloned()
    }

    // ── Message queue operations ──────────────────────────────────────────

    /// Enqueue an envelope for delivery to `recipient_id`.
    pub async fn enqueue(&self, recipient_id: String, envelope: StoredEnvelope) {
        self.queues
            .write()
            .await
            .entry(recipient_id)
            .or_default()
            .push_back(envelope);
    }

    /// Drain all pending envelopes for `user_id` (fetch-and-clear).
    pub async fn drain(&self, user_id: &str) -> Vec<StoredEnvelope> {
        self.queues
            .write()
            .await
            .remove(user_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Delete a single envelope by ID for `user_id`.
    pub async fn delete_message(&self, user_id: &str, message_id: &str) -> bool {
        let mut queues = self.queues.write().await;
        if let Some(queue) = queues.get_mut(user_id) {
            let before = queue.len();
            queue.retain(|e| e.id != message_id);
            return queue.len() < before;
        }
        false
    }
}
