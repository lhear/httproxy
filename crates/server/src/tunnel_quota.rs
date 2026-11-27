use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::constants::MAX_TUNNELS_PER_USER;

#[derive(Default)]
pub struct TunnelQuota {
    semaphores: DashMap<Arc<str>, Arc<Semaphore>>,
}

impl TunnelQuota {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_acquire(self: &Arc<Self>, user: &Arc<str>) -> Option<TunnelPermit> {
        let semaphore = self
            .semaphores
            .entry(Arc::clone(user))
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_TUNNELS_PER_USER)))
            .clone();
        let permit = semaphore.try_acquire_owned().ok()?;
        Some(TunnelPermit {
            quota: Arc::clone(self),
            user: Arc::clone(user),
            permit: Some(permit),
        })
    }
}

pub struct TunnelPermit {
    quota: Arc<TunnelQuota>,
    user: Arc<str>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for TunnelPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.quota
            .semaphores
            .remove_if(self.user.as_ref(), |_, sem| Arc::strong_count(sem) == 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> Arc<str> {
        Arc::from(name)
    }

    #[test]
    fn limit_is_per_user() {
        let quota = Arc::new(TunnelQuota::new());
        let alice = user("alice");

        let permits: Vec<TunnelPermit> = (0..MAX_TUNNELS_PER_USER)
            .map(|_| quota.try_acquire(&alice).expect("under limit"))
            .collect();

        assert!(quota.try_acquire(&alice).is_none());
        assert!(quota.try_acquire(&user("bob")).is_some());

        drop(permits);
        assert!(quota.try_acquire(&alice).is_some());
    }

    #[test]
    fn semaphore_is_dropped_once_idle() {
        let quota = Arc::new(TunnelQuota::new());
        let alice = user("alice");

        let first = quota.try_acquire(&alice).unwrap();
        let second = quota.try_acquire(&alice).unwrap();
        assert_eq!(quota.semaphores.len(), 1);

        drop(first);
        assert_eq!(quota.semaphores.len(), 1);
        drop(second);
        assert!(quota.semaphores.is_empty());
    }
}
