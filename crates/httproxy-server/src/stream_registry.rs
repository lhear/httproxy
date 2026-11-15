use dashmap::DashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use uuid::Uuid;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Active = 0,
    Consumed = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamQueryResult {
    Fresh,
    Active,
    Consumed,
}

#[derive(Debug)]
pub struct StreamConsumedError;

pub struct StreamRegistry {
    streams: DashMap<Uuid, (AtomicU8, u64)>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            streams: DashMap::new(),
        }
    }

    pub fn register(&self, stream_id: Uuid, now_secs: u64) -> bool {
        match self.streams.entry(stream_id) {
            dashmap::Entry::Occupied(_) => false,
            dashmap::Entry::Vacant(entry) => {
                entry.insert((AtomicU8::new(StreamState::Active as u8), now_secs));
                true
            }
        }
    }

    pub fn mark_consumed(&self, stream_id: Uuid) {
        if let Some(entry) = self.streams.get(&stream_id) {
            entry
                .0
                .store(StreamState::Consumed as u8, Ordering::Release);
        }
    }

    pub fn check(&self, stream_id: Uuid) -> StreamQueryResult {
        match self.streams.get(&stream_id) {
            None => StreamQueryResult::Fresh,
            Some(entry) => match entry.0.load(Ordering::Acquire) {
                s if s == StreamState::Active as u8 => StreamQueryResult::Active,
                _ => StreamQueryResult::Consumed,
            },
        }
    }

    pub fn remove_consumed_before(&self, cutoff_secs: u64) -> usize {
        let mut removed = 0;
        self.streams.retain(|_id, (state, ts)| {
            let keep =
                state.load(Ordering::Acquire) == StreamState::Active as u8 || *ts >= cutoff_secs;
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }

    pub fn shrink_to_fit(&self) {
        self.streams.shrink_to_fit();
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn dummy_ts() -> u64 {
        1_700_000_000
    }

    fn ids() -> (Uuid, Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn fresh_register_succeeds() {
        let reg = StreamRegistry::new();
        let (s1, _, _) = ids();
        assert!(reg.register(s1, dummy_ts()));
        assert_eq!(reg.check(s1), StreamQueryResult::Active);
    }

    #[test]
    fn duplicate_register_rejected() {
        let reg = StreamRegistry::new();
        let (s1, _, _) = ids();
        assert!(reg.register(s1, dummy_ts()));
        assert!(!reg.register(s1, dummy_ts()));
    }

    #[test]
    fn consumed_stream_reports_consumed() {
        let reg = StreamRegistry::new();
        let (s1, _, _) = ids();
        reg.register(s1, dummy_ts());
        reg.mark_consumed(s1);
        assert_eq!(reg.check(s1), StreamQueryResult::Consumed);
    }

    #[test]
    fn fresh_stream_returns_fresh() {
        let reg = StreamRegistry::new();
        let (_, s2, _) = ids();
        assert_eq!(reg.check(s2), StreamQueryResult::Fresh);
    }

    #[test]
    fn remove_consumed_before_removes_expired() {
        let reg = StreamRegistry::new();
        let (s1, s2, _) = ids();
        reg.register(s1, 100);
        reg.mark_consumed(s1);
        reg.register(s2, 200);
        let removed = reg.remove_consumed_before(150);
        assert_eq!(removed, 1);
        assert_eq!(reg.check(s1), StreamQueryResult::Fresh);
        assert_eq!(reg.check(s2), StreamQueryResult::Active);
    }

    #[test]
    fn remove_consumed_before_keeps_recent() {
        let reg = StreamRegistry::new();
        let (s1, _, _) = ids();
        reg.register(s1, 1000);
        reg.mark_consumed(s1);
        let removed = reg.remove_consumed_before(900);
        assert_eq!(removed, 0);
        assert_eq!(reg.check(s1), StreamQueryResult::Consumed);
    }

    #[test]
    fn concurrent_streams_independent() {
        let reg = StreamRegistry::new();
        let (s1, s2, _) = ids();
        assert!(reg.register(s1, dummy_ts()));
        assert!(reg.register(s2, dummy_ts()));
        reg.mark_consumed(s1);
        assert_eq!(reg.check(s1), StreamQueryResult::Consumed);
        assert_eq!(reg.check(s2), StreamQueryResult::Active);
    }

    #[tokio::test]
    async fn concurrent_registrations_different_ids() {
        let reg = Arc::new(StreamRegistry::new());
        let mut handles = Vec::new();

        for _ in 0..16u8 {
            let reg = Arc::clone(&reg);
            handles.push(tokio::spawn(async move {
                let id = Uuid::new_v4();
                reg.register(id, dummy_ts())
            }));
        }

        let mut success = 0;
        for handle in handles {
            if handle.await.unwrap() {
                success += 1;
            }
        }
        assert_eq!(
            success, 16,
            "all 16 concurrent registrations should succeed"
        );
    }

    #[tokio::test]
    async fn concurrent_register_and_consume_race() {
        let reg = Arc::new(StreamRegistry::new());
        let id = Uuid::new_v4();

        assert!(reg.register(id, dummy_ts()));

        let reg_clone = Arc::clone(&reg);
        let h1 = tokio::spawn(async move { reg_clone.register(id, dummy_ts()) });

        let reg_clone2 = Arc::clone(&reg);
        let h2 = tokio::spawn(async move {
            reg_clone2.mark_consumed(id);
        });

        let (r1, _) = tokio::join!(h1, h2);
        assert!(!r1.expect("register task should not panic"));
    }
}
