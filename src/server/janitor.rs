use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

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
        prune_expired_masters(&master_store, now);

        let cutoff = now.saturating_sub(MASTER_EXPIRY.as_secs());
        let pruned = stream_registry.remove_consumed_before(cutoff);
        if pruned > 0 {
            tracing::debug!(pruned, "pruned consumed stream registry entries");
            stream_registry.shrink_to_fit();
        }
    }
}

pub fn prune_expired_masters(
    master_store: &DashMap<String, super::MasterStoreEntry>,
    now: u64,
) -> usize {
    let expiry_limit = MASTER_EXPIRY.as_secs();
    let mut pruned = 0;
    master_store.retain(|session_id, (_, _, created)| {
        if now.saturating_sub(*created) >= expiry_limit {
            pruned += 1;
            tracing::info!(
                session_id = %session_id,
                "master key expired, removing from store"
            );
            false
        } else {
            true
        }
    });
    pruned
}

pub fn prune_dead_actors(actors: &DashMap<Uuid, SessionHandle>) -> usize {
    let mut pruned = 0;
    actors.retain(|stream_id, handle| {
        if handle.cmd_tx.is_closed() {
            pruned += 1;
            tracing::info!(
                stream_id = %stream_id,
                "stream actor channel closed, removing from actor map"
            );
            false
        } else {
            true
        }
    });
    pruned
}

pub async fn stream_janitor(actors: Arc<DashMap<Uuid, SessionHandle>>) {
    let mut interval = tokio::time::interval(JANITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        prune_dead_actors(&actors);

        actors.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::actor::tunnel::TunnelCmd;
    use crate::shaper::EncodingType;

    fn handle_pair() -> (SessionHandle, tokio::sync::mpsc::Receiver<TunnelCmd>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<TunnelCmd>(4);
        (
            SessionHandle {
                cmd_tx: tx,
                upload_cipher: None,
                encoding: EncodingType::Binary,
            },
            rx,
        )
    }

    #[test]
    fn prune_expired_masters_removes_old_keeps_fresh() {
        let store = Arc::new(DashMap::new());
        let now = 10_000u64;
        store.insert(
            "old".to_string(),
            (
                Arc::<str>::from("u"),
                zeroize::Zeroizing::new([0u8; 32]),
                now - 2000,
            ),
        );
        store.insert(
            "fresh".to_string(),
            (
                Arc::<str>::from("u"),
                zeroize::Zeroizing::new([0u8; 32]),
                now,
            ),
        );
        let pruned = prune_expired_masters(&store, now);
        assert_eq!(pruned, 1);
        assert!(!store.contains_key("old"));
        assert!(store.contains_key("fresh"));
    }

    #[test]
    fn prune_expired_masters_boundary() {
        let store = Arc::new(DashMap::new());
        let now = 10_000u64;
        store.insert(
            "boundary".to_string(),
            (
                Arc::<str>::from("u"),
                zeroize::Zeroizing::new([0u8; 32]),
                now - MASTER_EXPIRY.as_secs(),
            ),
        );
        let pruned = prune_expired_masters(&store, now);
        assert_eq!(pruned, 1);
    }

    #[test]
    fn prune_dead_actors_removes_closed_channels() {
        let actors = Arc::new(DashMap::new());
        let (handle1, rx1) = handle_pair();
        drop(rx1);
        actors.insert(Uuid::new_v4(), handle1);
        let (handle2, _rx2) = handle_pair();
        actors.insert(Uuid::new_v4(), handle2);
        let pruned = prune_dead_actors(&actors);
        assert_eq!(pruned, 1);
        assert_eq!(actors.len(), 1);
    }
}
