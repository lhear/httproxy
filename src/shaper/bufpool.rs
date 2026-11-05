use bytes::Bytes;
use std::cell::RefCell;

const MAX_FREE: usize = 64;
const MAX_BUFFER: usize = 4 * 1024 * 1024;
const MAX_BYTES: usize = 16 * 1024 * 1024;

struct Free {
    bufs: Vec<Vec<u8>>,
    bytes: usize,
}

thread_local! {
    static FREE: RefCell<Free> = const { RefCell::new(Free { bufs: Vec::new(), bytes: 0 }) };
}

pub fn take(min_capacity: usize) -> Vec<u8> {
    let reused = FREE.with(|free| {
        let mut free = free.borrow_mut();
        let mut best: Option<usize> = None;
        for (i, buf) in free.bufs.iter().enumerate() {
            if buf.capacity() < min_capacity {
                continue;
            }
            if best.is_none_or(|b| buf.capacity() < free.bufs[b].capacity()) {
                best = Some(i);
            }
        }
        let idx = best?;
        let buf = free.bufs.swap_remove(idx);
        free.bytes -= buf.capacity();
        Some(buf)
    });
    match reused {
        Some(mut buf) => {
            buf.clear();
            buf
        }
        None => Vec::with_capacity(min_capacity),
    }
}

fn put(mut buf: Vec<u8>) {
    let cap = buf.capacity();
    if !(1024..=MAX_BUFFER).contains(&cap) {
        return;
    }
    buf.clear();
    let _ = FREE.try_with(|free| {
        let mut free = free.borrow_mut();
        if free.bufs.len() >= MAX_FREE || free.bytes + cap > MAX_BYTES {
            return;
        }
        free.bytes += cap;
        free.bufs.push(buf);
    });
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

    #[test]
    fn reuse_returns_the_same_allocation() {
        let first = take(16 * 1024);
        let ptr = first.as_ptr();
        put(first);

        let second = take(8 * 1024);
        assert_eq!(
            second.as_ptr(),
            ptr,
            "buffer should come back from the pool"
        );
        assert!(second.capacity() >= 16 * 1024);
        assert!(second.is_empty());
    }

    #[test]
    fn take_prefers_the_smallest_fitting_buffer() {
        let small = take(4 * 1024);
        let small_ptr = small.as_ptr();
        let large = take(1024 * 1024);
        put(large);
        put(small);

        let picked = take(2 * 1024);
        assert_eq!(picked.as_ptr(), small_ptr, "best fit must win");
    }

    #[test]
    fn frame_bytes_recycles_on_drop() {
        let buf = take(16 * 1024);
        let ptr = buf.as_ptr();
        let bytes = frame_bytes(buf);
        assert_eq!(bytes.len(), 0);
        drop(bytes);

        let again = take(16 * 1024);
        assert_eq!(again.as_ptr(), ptr);
    }

    #[test]
    fn oversized_requests_allocate_fresh() {
        let huge = take(MAX_BUFFER + 1);
        assert!(huge.capacity() > MAX_BUFFER);
    }

    #[test]
    fn oversized_buffers_are_not_pooled() {
        let huge = Vec::with_capacity(MAX_BUFFER + 1);
        let ptr = huge.as_ptr();
        put(huge);

        let again = take(MAX_BUFFER + 1);
        assert_ne!(again.as_ptr(), ptr, "oversized buffer must not be reused");
    }
}
