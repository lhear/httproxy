use std::time::Duration;

use moka::future::Cache;

const CAPACITY: u64 = 4096;
const TTL: Duration = Duration::from_secs(300);

pub struct DnsCache(Cache<Vec<u8>, Vec<u8>>);

impl Default for DnsCache {
    fn default() -> Self {
        Self(
            Cache::builder()
                .max_capacity(CAPACITY)
                .time_to_live(TTL)
                .build(),
        )
    }
}

impl DnsCache {
    pub async fn response(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let mut response = self.0.get(&query[2..].to_vec()).await?;
        if response.len() < 12 {
            return None;
        }
        let id = u16::from_be_bytes([query[0], query[1]]);
        response[..2].copy_from_slice(&id.to_be_bytes());
        Some(response)
    }

    pub async fn store(&self, query: &[u8], response: &[u8]) {
        if query.len() < 12 || !cacheable(response) {
            return;
        }
        self.0.insert(query[2..].to_vec(), response.to_vec()).await;
    }
}

fn cacheable(response: &[u8]) -> bool {
    response.len() >= 12
        && response[2] & 0x80 != 0
        && response[2] & 0x02 == 0
        && matches!(response[3] & 0x0F, 0 | 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16) -> Vec<u8> {
        let mut query = vec![0; 12];
        query[..2].copy_from_slice(&id.to_be_bytes());
        query[2] = 1;
        query[5] = 1;
        query
    }

    fn response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response
    }

    #[tokio::test]
    async fn serves_a_cached_answer_under_a_new_id() {
        let cache = DnsCache::default();
        let first = query(0x1111);
        let answer = response(&first);
        cache.store(&first, &answer).await;

        let hit = cache.response(&query(0x2222)).await.expect("cache hit");
        assert_eq!(&hit[..2], &0x2222u16.to_be_bytes());
        assert_eq!(&hit[2..], &answer[2..]);
    }

    #[tokio::test]
    async fn skips_truncated_answers() {
        let cache = DnsCache::default();
        let question = query(1);
        let mut answer = response(&question);
        answer[2] |= 0x02;
        cache.store(&question, &answer).await;

        assert!(cache.response(&question).await.is_none());
    }

    #[tokio::test]
    async fn skips_error_answers() {
        let cache = DnsCache::default();
        let question = query(2);
        let mut answer = response(&question);
        answer[3] = (answer[3] & 0xF0) | 2;
        cache.store(&question, &answer).await;

        assert!(cache.response(&question).await.is_none());
    }

    #[tokio::test]
    async fn ignores_short_messages() {
        let cache = DnsCache::default();
        assert!(cache.response(&[0, 1, 2]).await.is_none());
        assert!(cache.response(&[]).await.is_none());
        cache.store(&[0, 1], &[0; 12]).await;
    }
}
