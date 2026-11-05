use bytes::Bytes;
use std::cell::RefCell;

const MAX_FREE: usize = 64;
const MAX_KEEP: usize = 256 * 1024;

thread_local! {
    static FREE: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

pub fn take(min_capacity: usize) -> Vec<u8> {
    let reused = FREE.with(|free| {
        let mut free = free.borrow_mut();
        let pos = free
            .iter()
            .position(|buf| buf.capacity() >= min_capacity && buf.capacity() <= MAX_KEEP)?;
        Some(free.swap_remove(pos))
    });
    match reused {
        Some(mut buf) => {
            buf.clear();
            buf
        }
        None => Vec::with_capacity(min_capacity),
    }
}

fn put(buf: Vec<u8>) {
    if buf.capacity() < 1024 || buf.capacity() > MAX_KEEP {
        return;
    }
    let _ = FREE.try_with(|free| {
        let mut free = free.borrow_mut();
        if free.len() < MAX_FREE {
            free.push(buf);
        }
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
    fn oversized_request_allocates_fresh() {
        let small = take(4 * 1024);
        put(small);
        let large = take(MAX_KEEP + 1);
        assert!(large.capacity() > MAX_KEEP);
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
    fn oversized_buffers_are_not_pooled() {
        let huge = Vec::with_capacity(MAX_KEEP + 1);
        put(huge);
        let buf = take(MAX_KEEP + 1);
        assert!(buf.capacity() > MAX_KEEP);
    }
}
