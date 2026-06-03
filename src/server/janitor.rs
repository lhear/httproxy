use dashmap::DashMap;
use std::sync::Arc;

use crate::server::SessionHandle;
use crate::server::constants::{JANITOR_INTERVAL, MASTER_EXPIRY, NONCE_CLEANUP_INTERVAL, now_secs};
use crate::server::nonce_registry::NonceRegistry;

pub async fn master_and_nonce_janitor(
    master_store: Arc<DashMap<String, super::MasterStoreEntry>>,
    nonce_registry: Arc<NonceRegistry>,
) {
    let mut interval = tokio::time::interval(NONCE_CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let mut has_deleted = false;
        let now = now_secs();
        let expiry_limit = MASTER_EXPIRY.as_secs();

        master_store.retain(|session_id, (_, _, created)| {
            if now.saturating_sub(*created) >= expiry_limit {
                nonce_registry.remove_session(session_id);
                has_deleted = true;
                false
            } else {
                true
            }
        });

        if has_deleted {
            master_store.shrink_to_fit();
            nonce_registry.shrink_to_fit();
        }
    }
}

pub async fn stream_janitor(actors: Arc<DashMap<String, SessionHandle>>) {
    let mut interval = tokio::time::interval(JANITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let mut has_deleted = false;

        actors.retain(|_, handle| {
            if handle.cmd_tx.is_closed() {
                has_deleted = true;
                false
            } else {
                true
            }
        });

        if has_deleted {
            actors.shrink_to_fit();
        }
    }
}
