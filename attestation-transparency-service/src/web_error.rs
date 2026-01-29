use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

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
        let err = format!("Something went wrong: {:?}", self.0);
        log::error!("{}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, err).into_response()
    }
}
