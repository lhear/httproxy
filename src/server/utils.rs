use rand::RngExt;
use uuid::Uuid;

use crate::error::ServerError;
use crate::server::constants::PADDING_POOL;

#[inline]
pub fn extract_cookie_value<'a>(headers: &'a axum::http::HeaderMap, key: &str) -> Option<&'a str> {
    let cookie_header = headers.get("Cookie")?.as_bytes();
    let cookie_str = std::str::from_utf8(cookie_header).ok()?;
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();

    let mut pos = 0;
    let haystack = cookie_str.as_bytes();
    let haystack_len = haystack.len();

    while pos < haystack_len {
        while pos < haystack_len && (haystack[pos] == b' ' || haystack[pos] == b';') {
            pos += 1;
        }
        if pos >= haystack_len {
            break;
        }

        if pos + key_len < haystack_len
            && &haystack[pos..pos + key_len] == key_bytes
            && haystack[pos + key_len] == b'='
        {
            let val_start = pos + key_len + 1;
            let val_end = memchr::memchr(b';', &haystack[val_start..])
                .map(|i| val_start + i)
                .unwrap_or(haystack_len);
            let val = &cookie_str[val_start..val_end];
            return Some(val.trim());
        }

        match memchr::memchr(b';', &haystack[pos..]) {
            Some(i) => pos += i + 1,
            None => break,
        }
    }
    None
}

#[inline]
pub fn validate_uuid(s: &str) -> Result<Uuid, ServerError> {
    Uuid::parse_str(s).map_err(|_| ServerError::bad_request("invalid UUID format"))
}

#[inline]
pub fn random_padding() -> &'static [u8] {
    let padding_len = rand::rng().random_range(30..=PADDING_POOL.len());
    &PADDING_POOL[..padding_len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn extract_cookie_basic() {
        let mut headers = HeaderMap::new();
        headers.insert("Cookie", "session=abc123; other=val".parse().unwrap());
        assert_eq!(extract_cookie_value(&headers, "session"), Some("abc123"));
        assert_eq!(extract_cookie_value(&headers, "other"), Some("val"));
        assert_eq!(extract_cookie_value(&headers, "missing"), None);
    }

    #[test]
    fn extract_cookie_no_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie_value(&headers, "session"), None);
    }

    #[test]
    fn random_padding_length() {
        for _ in 0..100 {
            let p = random_padding();
            assert!(p.len() >= 30);
            assert!(p.len() <= PADDING_POOL.len());
        }
    }
}
