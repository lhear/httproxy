use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};
use tracing::debug;

const CLASS_LIMITS: [usize; 14] = [
    1024, 2048, 4096, 8192, 16384, 20480, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152,
    4194304,
];
const CLASS_COUNT: usize = CLASS_LIMITS.len();
const MIN_BUFFER: usize = CLASS_LIMITS[0];
const MAX_BUFFER: usize = CLASS_LIMITS[CLASS_COUNT - 1];
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_PER_CLASS: usize = 8;
const IDLE_TTL: Duration = Duration::from_secs(30);
const REAP_INTERVAL: Duration = Duration::from_secs(10);

static TOTAL: AtomicUsize = AtomicUsize::new(0);
static REGISTRY: Mutex<Vec<Weak<Mutex<Free>>>> = Mutex::new(Vec::new());
static REAPER: OnceLock<()> = OnceLock::new();

thread_local! {
    static LOCAL: Arc<Mutex<Free>> = {
        let pool = Arc::new(Mutex::new(Free::new()));
        register(&pool);
        pool
    };
}

#[inline]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[inline]
fn class_of(capacity: usize) -> Option<usize> {
    if !(MIN_BUFFER..=MAX_BUFFER).contains(&capacity) {
        return None;
    }
    Some(CLASS_LIMITS.partition_point(|&limit| limit < capacity))
}

#[inline]
fn reserve(bytes: usize) -> bool {
    let mut total = TOTAL.load(Ordering::Relaxed);
    loop {
        let Some(next) = total.checked_add(bytes) else {
            return false;
        };
        if next > MAX_BYTES {
            return false;
        }
        match TOTAL.compare_exchange_weak(total, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(current) => total = current,
        }
    }
}

#[inline]
fn release(bytes: usize) {
    if bytes > 0 {
        TOTAL.fetch_sub(bytes, Ordering::Relaxed);
    }
}

struct Free {
    classes: [Vec<Vec<u8>>; CLASS_COUNT],
    last_use: [Option<Instant>; CLASS_COUNT],
    hits: u64,
    misses: u64,
}

impl Free {
    fn new() -> Self {
        Self {
            classes: std::array::from_fn(|_| Vec::new()),
            last_use: [None; CLASS_COUNT],
            hits: 0,
            misses: 0,
        }
    }

    fn take(&mut self, min_capacity: usize, now: Instant) -> Option<Vec<u8>> {
        let index = class_of(min_capacity)?;
        self.last_use[index] = Some(now);

        let mut best: Option<usize> = None;
        for (i, buf) in self.classes[index].iter().enumerate() {
            if buf.capacity() < min_capacity {
                continue;
            }
            if best.is_none_or(|b| buf.capacity() < self.classes[index][b].capacity()) {
                best = Some(i);
            }
        }

        let Some(best) = best else {
            self.misses += 1;
            return None;
        };
        let buf = self.classes[index].swap_remove(best);
        release(buf.capacity());
        self.hits += 1;
        Some(buf)
    }

    fn put(&mut self, buf: Vec<u8>, now: Instant) {
        let Some(index) = class_of(buf.capacity()) else {
            return;
        };
        self.last_use[index] = Some(now);

        if self.classes[index].len() >= MAX_PER_CLASS || !reserve(buf.capacity()) {
            return;
        }
        self.classes[index].push(buf);
    }

    fn trim_if_idle(&mut self, now: Instant) -> usize {
        let mut freed = 0;
        for index in 0..CLASS_COUNT {
            let idle =
                self.last_use[index].is_none_or(|at| now.saturating_duration_since(at) >= IDLE_TTL);
            if !idle || self.classes[index].is_empty() {
                continue;
            }
            freed += self.classes[index]
                .drain(..)
                .map(|buf| buf.capacity())
                .sum::<usize>();
        }
        release(freed);
        freed
    }

    fn counters(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

impl Drop for Free {
    fn drop(&mut self) {
        let freed: usize = self
            .classes
            .iter()
            .flat_map(|bucket| bucket.iter())
            .map(Vec::capacity)
            .sum();
        release(freed);
    }
}

fn register(pool: &Arc<Mutex<Free>>) {
    let mut registry = lock(&REGISTRY);
    registry.retain(|weak| weak.strong_count() > 0);
    registry.push(Arc::downgrade(pool));
}

fn ensure_reaper() {
    REAPER.get_or_init(|| {
        let _ = thread::Builder::new()
            .name("bufpool-reaper".to_owned())
            .spawn(|| {
                loop {
                    thread::sleep(REAP_INTERVAL);
                    reap(Instant::now());
                }
            });
    });
}

fn reap(now: Instant) {
    let pools: Vec<Arc<Mutex<Free>>> = {
        let mut registry = lock(&REGISTRY);
        registry.retain(|weak| weak.strong_count() > 0);
        registry.iter().filter_map(|weak| weak.upgrade()).collect()
    };

    let mut freed = 0;
    let mut hits = 0;
    let mut misses = 0;
    for pool in pools {
        let mut free = lock(pool.as_ref());
        freed += free.trim_if_idle(now);
        let (pool_hits, pool_misses) = free.counters();
        hits += pool_hits;
        misses += pool_misses;
    }
    if freed > 0 {
        debug!(
            bytes = freed,
            hits, misses, "buffer pool returned idle memory"
        );
    }
}

pub fn take(min_capacity: usize) -> Vec<u8> {
    if min_capacity == 0 {
        return Vec::new();
    }
    ensure_reaper();
    if min_capacity > MAX_BUFFER {
        return Vec::with_capacity(min_capacity);
    }

    let now = Instant::now();
    let reused = LOCAL
        .try_with(|pool| lock(pool.as_ref()).take(min_capacity, now))
        .unwrap_or(None);

    match reused {
        Some(mut buf) => {
            buf.clear();
            buf
        }
        None => Vec::with_capacity(min_capacity),
    }
}

fn put(mut buf: Vec<u8>) {
    let capacity = buf.capacity();
    if !(MIN_BUFFER..=MAX_BUFFER).contains(&capacity) {
        return;
    }
    ensure_reaper();
    buf.clear();
    let now = Instant::now();
    let _ = LOCAL.try_with(move |pool| lock(pool.as_ref()).put(buf, now));
}

struct PooledBuf {
    buf: Option<Vec<u8>>,
}

impl AsRef<[u8]> for PooledBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or(&[])
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            put(buf);
        }
    }
}

pub fn frame_bytes(buf: Vec<u8>) -> Bytes {
    Bytes::from_owner(PooledBuf { buf: Some(buf) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_local() {
        LOCAL.with(|pool| {
            lock(pool.as_ref()).trim_if_idle(Instant::now() + IDLE_TTL);
        });
    }

    #[test]
    fn class_boundaries() {
        assert_eq!(class_of(1023), None);
        assert_eq!(class_of(1024), Some(0));
        assert_eq!(class_of(1025), Some(1));
        assert_eq!(class_of(MAX_BUFFER), Some(CLASS_COUNT - 1));
        assert_eq!(class_of(MAX_BUFFER + 1), None);
    }

    #[test]
    fn fixed_frame_sizes_stay_below_the_32k_class() {
        assert_eq!(class_of(16424), class_of(18781));
        assert_ne!(class_of(18781), class_of(32768));
        assert!(class_of(16424) < class_of(32768));
    }

    #[test]
    fn zero_length_take_does_not_use_the_pool() {
        let buf = take(0);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn reuse_returns_the_same_allocation() {
        reset_local();
        let first = take(16 * 1024);
        let ptr = first.as_ptr();
        put(first);

        let second = take(16 * 1024);
        assert_eq!(
            second.as_ptr(),
            ptr,
            "buffer should come back from the pool"
        );
        assert!(second.capacity() >= 16 * 1024);
        assert!(second.is_empty());
    }

    #[test]
    fn take_prefers_the_smallest_fitting_buffer_within_a_class() {
        let now = Instant::now();
        let mut free = Free::new();
        let small = vec![0u8; 17 * 1024];
        let large = vec![0u8; 19 * 1024];
        assert_eq!(class_of(small.capacity()), class_of(large.capacity()));
        let large_ptr = large.as_ptr();
        free.put(small, now);
        free.put(large, now);

        let picked = free.take(18 * 1024, now).expect("the larger buffer fits");
        assert_eq!(
            picked.as_ptr(),
            large_ptr,
            "a too-small buffer must not win"
        );
        assert!(picked.capacity() >= 18 * 1024);
    }

    #[test]
    fn size_classes_do_not_lend_to_each_other() {
        let now = Instant::now();
        let mut free = Free::new();
        free.put(vec![0u8; 1024 * 1024], now);

        assert!(
            free.take(1024, now).is_none(),
            "a 1 KiB request must not take a 1 MiB buffer"
        );
        assert!(free.take(1024 * 1024, now).is_some());
    }

    #[test]
    fn frame_requests_do_not_take_batch_buffers() {
        let now = Instant::now();
        let mut free = Free::new();
        free.put(vec![0u8; 2 * 1024 * 1024], now);
        assert!(free.take(16424, now).is_none());
        assert!(free.take(18781, now).is_none());
    }

    #[test]
    fn per_class_limit_is_enforced() {
        let now = Instant::now();
        let mut free = Free::new();
        for _ in 0..MAX_PER_CLASS + 4 {
            free.put(Vec::with_capacity(1024), now);
        }
        assert_eq!(free.classes[0].len(), MAX_PER_CLASS);
    }

    #[test]
    fn idle_classes_are_returned_to_the_allocator() {
        let now = Instant::now();
        let mut free = Free::new();
        free.put(Vec::with_capacity(16 * 1024), now);

        assert_eq!(free.trim_if_idle(now), 0, "recently used classes stay");
        let later = now + IDLE_TTL + Duration::from_secs(1);
        assert_eq!(free.trim_if_idle(later), 16 * 1024);
        assert!(free.take(16 * 1024, later).is_none());
    }

    #[test]
    fn counters_track_reuse() {
        let now = Instant::now();
        let mut free = Free::new();
        assert!(free.take(1024, now).is_none());
        free.put(Vec::with_capacity(1024), now);
        assert!(free.take(1024, now).is_some());
        assert_eq!(free.counters(), (1, 1));
    }

    #[test]
    fn budget_rejects_oversized_reservations() {
        assert!(!reserve(MAX_BYTES + 1));
    }

    #[test]
    fn oversized_buffers_are_not_pooled() {
        reset_local();
        put(Vec::with_capacity(MAX_BUFFER + 1));

        let pooled = LOCAL
            .try_with(|pool| {
                lock(pool.as_ref())
                    .classes
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>()
            })
            .unwrap_or(0);
        assert_eq!(pooled, 0, "oversized buffer must not be pooled");
    }

    #[test]
    fn oversized_requests_allocate_fresh() {
        let huge = take(MAX_BUFFER + 1);
        assert!(huge.capacity() > MAX_BUFFER);
    }

    #[test]
    fn frame_bytes_recycles_on_drop() {
        reset_local();
        let buf = take(16 * 1024);
        let ptr = buf.as_ptr();
        let bytes = frame_bytes(buf);
        assert_eq!(bytes.len(), 0);
        drop(bytes);

        let again = take(16 * 1024);
        assert_eq!(again.as_ptr(), ptr);
    }
}
