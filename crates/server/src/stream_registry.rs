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
pub struct StreamRegistry {
    streams: DashMap<Uuid, (AtomicU8, u64)>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            streams: DashMap::new(),
        }
    }

    pub fn register(&self, stream_id: Uuid, monotonic_secs: u64) -> bool {
        match self.streams.entry(stream_id) {
            dashmap::Entry::Occupied(_) => false,
            dashmap::Entry::Vacant(entry) => {
                entry.insert((AtomicU8::new(StreamState::Active as u8), monotonic_secs));
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
}
