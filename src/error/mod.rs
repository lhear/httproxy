use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;

#[derive(Debug)]
pub enum HttpProxyError {
    Anyhow(anyhow::Error),
    Io(std::io::Error),
    Protocol(String),
    Config(String),
    Auth(String),
    Dns(String),
    Timeout(String),
    NotFound(String),
    Precondition(String),
    PayloadTooLarge(String),
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anyhow(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
            Self::Config(m) => write!(f, "config error: {m}"),
            Self::Auth(m) => write!(f, "auth error: {m}"),
            Self::Dns(m) => write!(f, "dns error: {m}"),
            Self::Timeout(m) => write!(f, "timeout: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Precondition(m) => write!(f, "precondition: {m}"),
            Self::PayloadTooLarge(m) => write!(f, "payload too large: {m}"),
        }
    }
}

impl std::error::Error for HttpProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Anyhow(e) => Some(e.as_ref()),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for HttpProxyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Anyhow(e)
    }
}

impl From<std::io::Error> for HttpProxyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone)]
pub struct ServerError(pub StatusCode, pub String);

impl ServerError {
    #[inline]
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
    #[inline]
    pub fn bad_gateway(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_GATEWAY, msg.into())
    }
    #[inline]
    pub fn gateway_timeout(msg: impl Into<String>) -> Self {
        Self(StatusCode::GATEWAY_TIMEOUT, msg.into())
    }
    #[inline]
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self(StatusCode::UNAUTHORIZED, msg.into())
    }
    #[inline]
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, msg.into())
    }
    #[inline]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
    #[inline]
    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        Self(StatusCode::PAYLOAD_TOO_LARGE, msg.into())
    }
    #[inline]
    pub fn precondition_required(msg: impl Into<String>) -> Self {
        Self(StatusCode::PRECONDITION_REQUIRED, msg.into())
    }
    #[inline]
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, msg.into())
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        Self::internal(err.to_string())
    }
}

impl From<ServerError> for HttpProxyError {
    fn from(e: ServerError) -> Self {
        Self::Protocol(e.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_and_source() {
        let io_err = HttpProxyError::Io(std::io::Error::other("boom"));
        assert!(io_err.to_string().contains("boom"));
        assert!(std::error::Error::source(&io_err).is_some());

        let proto_err = HttpProxyError::Protocol("bad frame".into());
        assert_eq!(proto_err.to_string(), "protocol error: bad frame");
        assert!(std::error::Error::source(&proto_err).is_none());
    }

    #[test]
    fn app_error_constructors() {
        assert_eq!(ServerError::bad_request("x").0, StatusCode::BAD_REQUEST);
        assert_eq!(ServerError::bad_gateway("x").0, StatusCode::BAD_GATEWAY);
        assert_eq!(
            ServerError::gateway_timeout("x").0,
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(ServerError::unauthorized("x").0, StatusCode::UNAUTHORIZED);
        assert_eq!(ServerError::not_found("x").0, StatusCode::NOT_FOUND);
        assert_eq!(
            ServerError::internal("x").0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ServerError::payload_too_large("x").0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ServerError::precondition_required("x").0,
            StatusCode::PRECONDITION_REQUIRED
        );
        assert_eq!(
            ServerError::service_unavailable("x").0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn app_error_into_response() {
        let err = ServerError::bad_request("test");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn app_error_from_std_error() {
        let io = std::io::Error::other("oops");
        let app: ServerError = io.into();
        assert_eq!(app.0, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
