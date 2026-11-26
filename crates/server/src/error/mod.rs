use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

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
    pub fn request_timeout(msg: impl Into<String>) -> Self {
        Self(StatusCode::REQUEST_TIMEOUT, msg.into())
    }
    #[inline]
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self(StatusCode::UNAUTHORIZED, msg.into())
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
