// handlers: This module deals with httpd route handlers.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use axum::extract::State;
use axum::http::{
    header,
    HeaderMap,
    HeaderValue,
    StatusCode,
};
use axum::response::{
    Html,
    IntoResponse,
};
use parking_lot::Mutex;
use std::sync::Arc;
use super::{
    AppState,
    AppExporter,
};
use super::Collector;
use tracing::debug;

// If we don't set this as the content-type header, Prometheus will not ingest
// the metrics properly, complaining about the INFO metric type.
const OPENMETRICS_HEADER: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";
const TEXT_HTML_UTF8_HEADER: &str = "text/html; charset=utf-8";

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
#[allow(clippy::unused_async)]
pub async fn index(State(data): State<Arc<AppState>>) -> impl IntoResponse {
    debug!("Displaying index page");

    Html(data.index_page.clone())
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
#[allow(clippy::unused_async)]
pub async fn metrics(State(data): State<Arc<Mutex<AppExporter>>>)
-> impl IntoResponse {
    debug!("Processing metrics request");

    let data = data.lock();

    // Get the exporter from the state
    let exporter = &(data.exporter);

    // We always want a HeaderMap
    let mut headers = HeaderMap::new();

    // Exporter could fail.
    match exporter.collect() {
        Ok(metrics) => {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(OPENMETRICS_HEADER),
            );

            (
                StatusCode::OK,
                headers,
                metrics,
            )
        },
        Err(e) => {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(TEXT_HTML_UTF8_HEADER),
            );

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                headers,
                format!("{e}"),
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{
            header::CONTENT_TYPE,
            Request,
        },
        routing::get,
        Router,
    };
    use pretty_assertions::assert_eq;
    use tower::ServiceExt;

    fn app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/", get(index))
            .with_state(state)
    }

    #[tokio::test]
    async fn index_ok() {
        let state = AppState {
            index_page: "Test Body".into(),

            #[cfg(feature = "auth")]
            basic_auth_config: Default::default(),
        };

        let app = app(Arc::new(state));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert!(response.status().is_success());

        let headers = response.headers();
        let content_type = headers
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "text/html; charset=utf-8");

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(body, "Test Body".as_bytes());
    }
}
