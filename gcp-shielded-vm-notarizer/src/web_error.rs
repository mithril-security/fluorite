//! Error handling for the web API

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Application error type that wraps anyhow::Error
pub struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {:?}", self.0),
        )
            .into_response()
    }
}
