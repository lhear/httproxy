use dashmap::DashMap;
use std::sync::Arc;

use crate::server::SessionHandle;
use crate::server::constants::{
    JANITOR_INTERVAL, MASTER_CLEANUP_INTERVAL, MASTER_EXPIRY, now_secs,
};
use crate::server::stream_registry::StreamRegistry;

pub async fn master_and_stream_janitor(
    master_store: Arc<DashMap<String, super::MasterStoreEntry>>,
    stream_registry: Arc<StreamRegistry>,
) {
    let mut interval = tokio::time::interval(MASTER_CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let now = now_secs();
        let expiry_limit = MASTER_EXPIRY.as_secs();

        master_store.retain(|session_id, (_, _, created)| {
            if now.saturating_sub(*created) >= expiry_limit {
                tracing::info!(
                    session_id = %session_id,
                    "master key expired, removing from store"
                );
                false
            } else {
                true
            }
        });

        let cutoff = now.saturating_sub(expiry_limit);
        let pruned = stream_registry.remove_consumed_before(cutoff);
        if pruned > 0 {
            tracing::debug!(pruned, "pruned consumed stream registry entries");
            stream_registry.shrink_to_fit();
        }
    }
}

pub async fn stream_janitor(actors: Arc<DashMap<String, SessionHandle>>) {
    let mut interval = tokio::time::interval(JANITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        actors.retain(|stream_id, handle| {
            if handle.cmd_tx.is_closed() {
                tracing::info!(
                    stream_id = %stream_id,
                    "stream actor channel closed, removing from actor map"
                );
                false
            } else {
                true
            }
        });

        actors.shrink_to_fit();
    }
}
