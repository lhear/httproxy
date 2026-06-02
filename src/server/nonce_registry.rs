use dashmap::DashMap;
use std::sync::atomic::{AtomicU8, Ordering};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceState {
    Active = 0,
    Consumed = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceQueryResult {
    Fresh,
    Active,
    Consumed,
}

#[derive(Debug)]
pub struct NonceConsumedError;

pub struct NonceRegistry {
    sessions: DashMap<String, DashMap<[u8; 16], AtomicU8>>,
}

impl NonceRegistry {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn try_claim(
        &self,
        session_id: &str,
        conn_nonce: &[u8; 16],
    ) -> Result<bool, NonceConsumedError> {
        let per_session = self.sessions.entry(session_id.to_owned()).or_default();

        match per_session.entry(*conn_nonce) {
            dashmap::Entry::Occupied(entry) => {
                let existing = entry.get().load(Ordering::Acquire);
                if existing == NonceState::Active as u8 {
                    Ok(false)
                } else {
                    Err(NonceConsumedError)
                }
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(AtomicU8::new(NonceState::Active as u8));
                Ok(true)
            }
        }
    }

    pub fn mark_consumed(&self, session_id: &str, conn_nonce: &[u8; 16]) {
        if let Some(per_session) = self.sessions.get(session_id)
            && let Some(entry) = per_session.get(conn_nonce)
        {
            entry.store(NonceState::Consumed as u8, Ordering::Release);
        }
    }

    pub fn check_nonce(&self, session_id: &str, conn_nonce: &[u8; 16]) -> NonceQueryResult {
        match self.sessions.get(session_id) {
            None => NonceQueryResult::Fresh,
            Some(per_session) => match per_session.get(conn_nonce) {
                None => NonceQueryResult::Fresh,
                Some(entry) => match entry.load(Ordering::Acquire) {
                    s if s == NonceState::Active as u8 => NonceQueryResult::Active,
                    _ => NonceQueryResult::Consumed,
                },
            },
        }
    }

    pub fn remove_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn shrink_to_fit(&self) {
        self.sessions.shrink_to_fit();
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn fresh_claim_succeeds() {
        let reg = NonceRegistry::new();
        let nonce = [0xAA; 16];
        assert!(matches!(reg.try_claim("s1", &nonce), Ok(true)));
    }

    #[test]
    fn active_nonce_reports_active() {
        let reg = NonceRegistry::new();
        let nonce = [0xBB; 16];
        reg.try_claim("s1", &nonce).unwrap();
        assert_eq!(reg.check_nonce("s1", &nonce), NonceQueryResult::Active);
    }

    #[test]
    fn consumed_nonce_reports_consumed() {
        let reg = NonceRegistry::new();
        let nonce = [0xCC; 16];
        reg.try_claim("s1", &nonce).unwrap();
        reg.mark_consumed("s1", &nonce);
        assert_eq!(reg.check_nonce("s1", &nonce), NonceQueryResult::Consumed);
    }

    #[test]
    fn consumed_nonce_rejects_replay() {
        let reg = NonceRegistry::new();
        let nonce = [0xDD; 16];
        reg.try_claim("s1", &nonce).unwrap();
        reg.mark_consumed("s1", &nonce);
        assert!(reg.try_claim("s1", &nonce).is_err());
    }

    #[test]
    fn active_nonce_allows_duplicate_claim() {
        let reg = NonceRegistry::new();
        let nonce = [0xEE; 16];
        assert!(reg.try_claim("s1", &nonce).unwrap());
        assert!(matches!(reg.try_claim("s1", &nonce), Ok(false)));
        assert_eq!(reg.check_nonce("s1", &nonce), NonceQueryResult::Active);
    }

    #[test]
    fn remove_session_clears_all_nonces() {
        let reg = NonceRegistry::new();
        reg.try_claim("s1", &[1u8; 16]).unwrap();
        reg.try_claim("s1", &[2u8; 16]).unwrap();
        reg.remove_session("s1");
        assert_eq!(reg.check_nonce("s1", &[1u8; 16]), NonceQueryResult::Fresh);
        assert_eq!(reg.check_nonce("s1", &[2u8; 16]), NonceQueryResult::Fresh);
    }

    #[test]
    fn concurrent_sessions_independent() {
        let reg = NonceRegistry::new();
        let n1 = [1u8; 16];
        let n2 = [2u8; 16];
        reg.try_claim("s1", &n1).unwrap();
        reg.try_claim("s2", &n2).unwrap();
        reg.mark_consumed("s1", &n1);
        assert_eq!(reg.check_nonce("s1", &n1), NonceQueryResult::Consumed);
        assert_eq!(reg.check_nonce("s2", &n2), NonceQueryResult::Active);
    }

    #[test]
    fn fresh_nonce_returns_fresh() {
        let reg = NonceRegistry::new();
        assert_eq!(
            reg.check_nonce("nonexistent", &[0xFF; 16]),
            NonceQueryResult::Fresh
        );
    }

    #[tokio::test]
    async fn concurrent_claims_different_nonces() {
        let reg = Arc::new(NonceRegistry::new());
        let mut handles = Vec::new();

        for i in 0..16u8 {
            let reg = Arc::clone(&reg);
            handles.push(tokio::spawn(async move {
                let nonce = [i; 16];
                reg.try_claim("concurrent-session", &nonce)
            }));
        }

        let mut success = 0;
        for handle in handles {
            if let Ok(true) = handle.await.unwrap() {
                success += 1
            }
        }
        assert_eq!(success, 16, "all 16 concurrent claims should succeed");
    }

    #[tokio::test]
    async fn concurrent_claim_and_consume_race() {
        let reg = Arc::new(NonceRegistry::new());
        let nonce = [0x42u8; 16];

        assert!(matches!(reg.try_claim("race-session", &nonce), Ok(true)));

        let reg_clone = Arc::clone(&reg);
        let h1 = tokio::spawn(async move { reg_clone.try_claim("race-session", &nonce) });

        let reg_clone2 = Arc::clone(&reg);
        let h2 = tokio::spawn(async move {
            reg_clone2.mark_consumed("race-session", &nonce);
        });

        let (r1, _) = tokio::join!(h1, h2);
        match r1.expect("claim task should not panic") {
            Ok(false) => {}
            Err(NonceConsumedError) => {}
            Ok(true) => panic!("should not claim an already-Active nonce"),
        }
    }

    #[tokio::test]
    async fn concurrent_remove_and_claim_race() {
        let reg = Arc::new(NonceRegistry::new());
        let nonce = [0x99u8; 16];

        assert!(matches!(reg.try_claim("remove-session", &nonce), Ok(true)));

        let reg_clone = Arc::clone(&reg);
        let h1 = tokio::spawn(async move {
            reg_clone.remove_session("remove-session");
        });

        let other_nonce = [0x88u8; 16];
        let _ = reg.try_claim("remove-session", &other_nonce);

        h1.await.unwrap();

        assert_eq!(
            reg.check_nonce("remove-session", &nonce),
            NonceQueryResult::Fresh
        );
        assert_eq!(
            reg.check_nonce("remove-session", &other_nonce),
            NonceQueryResult::Fresh
        );
    }
}
