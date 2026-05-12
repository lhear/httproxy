use dashmap::{DashMap, DashSet};
use std::sync::Arc;
use tracing::warn;

use crate::server::constants::{JANITOR_INTERVAL, MASTER_EXPIRY, NONCE_CLEANUP_INTERVAL, now_secs};
use crate::server::state::UploadStream;

pub async fn stream_janitor(streams: Arc<DashMap<String, Arc<UploadStream>>>) {
    let mut interval = tokio::time::interval(JANITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut expired = vec![];
        for entry in streams.iter() {
            let stream = entry.value();
            if stream.is_idle() && stream.do_shutdown() {
                expired.push(entry.key().clone());
            }
        }
        for key in expired {
            streams.remove(&key);
            let display_id = key.split(':').next().unwrap_or(&key);
            warn!(stream_id = %display_id, reason = "idle timeout", "shutting down idle stream");
        }
    }
}

pub async fn master_and_nonce_janitor(
    master_store: Arc<DashMap<String, super::MasterStoreEntry>>,
    used_nonces: Arc<DashMap<String, DashSet<[u8; 16]>>>,
) {
    let mut interval = tokio::time::interval(NONCE_CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        master_store.retain(|session_id, (_, _master, created)| {
            if now_secs().saturating_sub(*created) >= MASTER_EXPIRY.as_secs() {
                used_nonces.remove(session_id);
                false
            } else {
                true
            }
        });
    }
}
