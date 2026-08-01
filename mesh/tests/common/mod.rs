//! Shared test-only helpers for `parda-mesh`'s integration tests.
//! Mirrors `mixnode/tests/common/`'s role for that crate.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use parda_protocol::{
    envelope::MessageEnvelope,
    error::{PardaError, Result as ProtoResult},
    transport::TransportLayer,
};

/// A trivial in-memory stand-in for `DirectTransport`/`MixTransport`
/// (Sub-Phase 4D's hybrid-handoff and combined-scenario tests don't need
/// a real HTTP relay to prove hybrid *routing logic* is correct — the
/// same reasoning `mixnode`'s own tests apply to using real loopback
/// daemons instead of a physical network: what's under test is the
/// protocol/transport logic, not a specific wire implementation).
/// Toggleable "up"/"down" via [`MockOnlineTransport::set_up`] to
/// simulate connectivity dropping and returning.
#[derive(Clone)]
pub struct MockOnlineTransport {
    up: Arc<AtomicBool>,
    store: Arc<Mutex<HashMap<String, Vec<MessageEnvelope>>>>,
}

impl MockOnlineTransport {
    pub fn new() -> Self {
        Self {
            up: Arc::new(AtomicBool::new(true)),
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
    }
}

#[async_trait]
impl TransportLayer for MockOnlineTransport {
    async fn send(&self, envelope: &MessageEnvelope) -> ProtoResult<()> {
        if !self.up.load(Ordering::SeqCst) {
            return Err(PardaError::Transport("mock online transport is down".to_string()));
        }
        self.store
            .lock()
            .unwrap()
            .entry(envelope.recipient_id.clone())
            .or_default()
            .push(envelope.clone());
        Ok(())
    }

    async fn receive(&self, recipient_id: &str) -> ProtoResult<Vec<MessageEnvelope>> {
        if !self.up.load(Ordering::SeqCst) {
            return Err(PardaError::Transport("mock online transport is down".to_string()));
        }
        Ok(self.store.lock().unwrap().remove(recipient_id).unwrap_or_default())
    }
}
