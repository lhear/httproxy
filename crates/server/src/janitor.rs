use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::SessionHandle;
use crate::constants::{
    JANITOR_INTERVAL, MASTER_CLEANUP_INTERVAL, MASTER_EXPIRY, MAX_SESSIONS_PER_USER, monotonic_secs,
};
use crate::stream_registry::StreamRegistry;

pub async fn master_and_stream_janitor(
    master_store: Arc<DashMap<String, super::MasterStoreEntry>>,
    stream_registry: Arc<StreamRegistry>,
) {
    let mut interval = tokio::time::interval(MASTER_CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let now = monotonic_secs();
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

pub fn ensure_user_session_quota(
    master_store: &DashMap<String, super::MasterStoreEntry>,
    user: &str,
    now: u64,
) {
    let expiry_limit = MASTER_EXPIRY.as_secs();
    let mut live: Vec<(u64, String)> = master_store
        .iter()
        .filter(|entry| {
            let (owner, _, created) = entry.value();
            owner.as_ref() == user && now.saturating_sub(*created) < expiry_limit
        })
        .map(|entry| (entry.value().2, entry.key().clone()))
        .collect();

    if live.len() < MAX_SESSIONS_PER_USER {
        return;
    }

    let evict = live.len() - MAX_SESSIONS_PER_USER + 1;
    live.select_nth_unstable(evict - 1);
    live.truncate(evict);
    let evicted = live
        .into_iter()
        .filter(|(_, key)| master_store.remove(key).is_some())
        .count();

    tracing::debug!(user, evicted, "evicted oldest sessions over user quota");
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

    fn insert_session(
        store: &DashMap<String, crate::MasterStoreEntry>,
        key: &str,
        user: &str,
        created: u64,
    ) {
        store.insert(
            key.to_string(),
            (
                Arc::<str>::from(user),
                zeroize::Zeroizing::new([0u8; 32]),
                created,
            ),
        );
    }

    fn count_user(store: &DashMap<String, crate::MasterStoreEntry>, user: &str) -> usize {
        store
            .iter()
            .filter(|entry| entry.value().0.as_ref() == user)
            .count()
    }

    #[test]
    fn user_quota_evicts_oldest_of_that_user_only() {
        let store = DashMap::new();
        let now = 50_000u64;
        for i in 0..MAX_SESSIONS_PER_USER as u64 {
            insert_session(&store, &format!("a{i:02}"), "alice", now - 1000 + i);
        }
        for i in 0..3u64 {
            insert_session(&store, &format!("b{i:02}"), "bob", now - 1000 + i);
        }

        ensure_user_session_quota(&store, "alice", now);
        assert!(!store.contains_key("a00"));
        assert!(store.contains_key("a01"));
        assert_eq!(count_user(&store, "alice"), MAX_SESSIONS_PER_USER - 1);
        assert_eq!(count_user(&store, "bob"), 3);
    }

    #[test]
    fn user_quota_evicts_exactly_one_when_timestamps_tie() {
        let store = DashMap::new();
        let now = 50_000u64;
        for i in 0..MAX_SESSIONS_PER_USER {
            insert_session(&store, &format!("s{i:02}"), "alice", now);
        }

        ensure_user_session_quota(&store, "alice", now);
        assert_eq!(store.len(), MAX_SESSIONS_PER_USER - 1);
    }

    #[test]
    fn user_quota_ignores_expired_sessions() {
        let store = DashMap::new();
        let now = 50_000u64;
        let expired_at = now - MASTER_EXPIRY.as_secs() - 1;
        for i in 0..MAX_SESSIONS_PER_USER as u64 {
            insert_session(&store, &format!("stale{i:02}"), "alice", expired_at);
        }
        for i in 0..(MAX_SESSIONS_PER_USER - 1) as u64 {
            insert_session(&store, &format!("live{i:02}"), "alice", now - 10 + i);
        }

        ensure_user_session_quota(&store, "alice", now);
        assert_eq!(store.len(), MAX_SESSIONS_PER_USER * 2 - 1);
        for i in 0..(MAX_SESSIONS_PER_USER - 1) as u64 {
            assert!(store.contains_key(&format!("live{i:02}")));
        }
    }

    #[test]
    fn user_quota_evicts_enough_sessions_to_admit_one() {
        let store = DashMap::new();
        let now = 50_000u64;
        for i in 0..MAX_SESSIONS_PER_USER + 8 {
            insert_session(&store, &format!("s{i:02}"), "alice", now - 500 + i as u64);
        }

        ensure_user_session_quota(&store, "alice", now);
        assert_eq!(store.len(), MAX_SESSIONS_PER_USER - 1);
        assert!(!store.contains_key("s08"));
        assert!(store.contains_key("s09"));
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
