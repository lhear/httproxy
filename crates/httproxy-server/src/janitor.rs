use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::SessionHandle;
use crate::constants::{JANITOR_INTERVAL, MASTER_CLEANUP_INTERVAL, MASTER_EXPIRY, now_secs};
use crate::stream_registry::StreamRegistry;

pub async fn master_and_stream_janitor(
    master_store: Arc<DashMap<String, super::MasterStoreEntry>>,
    stream_registry: Arc<StreamRegistry>,
) {
    let mut interval = tokio::time::interval(MASTER_CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let now = now_secs();
        let pruned = prune_expired_masters(&master_store, now);
        if pruned > 0 {
            tracing::debug!(pruned, "pruned expired master sessions");
        }
        shrink_if_sparse(&master_store);

        let cutoff = now.saturating_sub(MASTER_EXPIRY.as_secs());
        let pruned = stream_registry.remove_consumed_before(cutoff);
        if pruned > 0 {
            tracing::debug!(pruned, "pruned consumed stream registry entries");
            stream_registry.shrink_to_fit();
        }
    }
}

fn shrink_if_sparse<K: Eq + std::hash::Hash, V>(map: &DashMap<K, V>) {
    if map.capacity() > map.len() * 2 {
        map.shrink_to_fit();
    }
}

pub fn prune_expired_masters(
    master_store: &DashMap<String, super::MasterStoreEntry>,
    now: u64,
) -> usize {
    let expiry_limit = MASTER_EXPIRY.as_secs();
    let mut pruned = 0;
    master_store.retain(|_, (_, _, created)| {
        let expired = now.saturating_sub(*created) >= expiry_limit;
        pruned += usize::from(expired);
        !expired
    });
    pruned
}

const EVICT_BATCH_DIVISOR: usize = 8;

pub fn ensure_session_capacity(
    master_store: &DashMap<String, super::MasterStoreEntry>,
    now: u64,
    capacity: usize,
) {
    if master_store.len() < capacity {
        return;
    }
    prune_expired_masters(master_store, now);
    if master_store.len() < capacity {
        return;
    }
    let batch = (capacity / EVICT_BATCH_DIVISOR).max(1);
    let evicted = evict_oldest_sessions(master_store, batch);
    tracing::debug!(
        capacity,
        evicted,
        "master session store full, evicted oldest sessions"
    );
}

fn evict_oldest_sessions(
    master_store: &DashMap<String, super::MasterStoreEntry>,
    count: usize,
) -> usize {
    let mut created: Vec<u64> = master_store.iter().map(|entry| entry.value().2).collect();
    if created.is_empty() {
        return 0;
    }
    let index = count.min(created.len()) - 1;
    let (_, cutoff, _) = created.select_nth_unstable(index);
    let cutoff = *cutoff;
    let mut evicted = 0;
    master_store.retain(|_, (_, _, ts)| {
        let keep = *ts > cutoff;
        evicted += usize::from(!keep);
        keep
    });
    evicted
}

pub fn prune_dead_actors(actors: &DashMap<Uuid, SessionHandle>) -> usize {
    let mut pruned = 0;
    actors.retain(|_, handle| {
        let dead = handle.cmd_tx.is_closed();
        pruned += usize::from(dead);
        !dead
    });
    pruned
}

pub async fn stream_janitor(actors: Arc<DashMap<Uuid, SessionHandle>>) {
    let mut interval = tokio::time::interval(JANITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let pruned = prune_dead_actors(&actors);
        if pruned > 0 {
            tracing::debug!(pruned, "pruned closed stream actors");
        }
        shrink_if_sparse(&actors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::tunnel::TunnelCmd;
    use httproxy_core::shaper::EncodingType;

    fn handle_pair() -> (SessionHandle, tokio::sync::mpsc::Receiver<TunnelCmd>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<TunnelCmd>(4);
        let (upload_tx, _upload_rx) =
            tokio::sync::mpsc::channel::<crate::actor::upload::UploadCmd>(4);
        (
            SessionHandle {
                cmd_tx: tx,
                upload_tx,
                upload_cipher: Arc::new(httproxy_core::crypto::AesFrameCipher::new(
                    &zeroize::Zeroizing::new([7u8; 32]),
                )),
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

    fn insert_session(store: &DashMap<String, crate::MasterStoreEntry>, key: &str, created: u64) {
        store.insert(
            key.to_string(),
            (
                Arc::<str>::from("u"),
                zeroize::Zeroizing::new([0u8; 32]),
                created,
            ),
        );
    }

    #[test]
    fn ensure_session_capacity_keeps_sessions_below_limit() {
        let store = DashMap::new();
        for i in 0..4 {
            insert_session(&store, &format!("s{i}"), 100 + i);
        }
        ensure_session_capacity(&store, 1_000, 8);
        assert_eq!(store.len(), 4);
    }

    #[test]
    fn ensure_session_capacity_prunes_expired_before_evicting() {
        let store = DashMap::new();
        let now = 10_000u64;
        insert_session(&store, "expired", now - MASTER_EXPIRY.as_secs());
        insert_session(&store, "fresh-a", now - 10);
        insert_session(&store, "fresh-b", now - 5);
        ensure_session_capacity(&store, now, 3);
        assert_eq!(store.len(), 2);
        assert!(!store.contains_key("expired"));
        assert!(store.contains_key("fresh-a"));
        assert!(store.contains_key("fresh-b"));
    }

    #[test]
    fn ensure_session_capacity_evicts_oldest_when_full() {
        let store = DashMap::new();
        let now = 50_000u64;
        for i in 0..16u64 {
            insert_session(&store, &format!("s{i:02}"), now - 100 + i);
        }
        ensure_session_capacity(&store, now, 16);
        assert_eq!(store.len(), 14);
        assert!(!store.contains_key("s00"));
        assert!(!store.contains_key("s01"));
        assert!(store.contains_key("s15"));
    }

    #[test]
    fn shrink_if_sparse_releases_capacity() {
        let map: DashMap<u64, u64> = DashMap::new();
        for i in 0..4096 {
            map.insert(i, i);
        }
        map.clear();
        let before = map.capacity();
        shrink_if_sparse(&map);
        assert!(map.capacity() < before);
    }

    #[test]
    fn shrink_if_sparse_keeps_dense_map() {
        let map: DashMap<u64, u64> = DashMap::new();
        for i in 0..4096 {
            map.insert(i, i);
        }
        let before = map.capacity();
        shrink_if_sparse(&map);
        assert_eq!(map.capacity(), before);
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
