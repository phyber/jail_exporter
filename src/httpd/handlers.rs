// handlers: This module deals with httpd route handlers.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use actix_web::HttpResponse;
use actix_web::http::header::{
    self,
    ContentType,
};
use actix_web::web::Data;
use log::debug;
use std::sync::Mutex;
use super::{
    AppState,
    AppExporter,
};
use super::Collector;

// If we don't set this as the content-type header, Prometheus will not ingest
// the metrics properly, complaining about the INFO metric type.
const OPEN_METRICS_VERSION: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
pub(in crate::httpd) async fn index(data: Data<AppState>) -> HttpResponse {
    debug!("Displaying index page");

    HttpResponse::Ok()
        .insert_header(ContentType::html())
        .body(data.index_page.clone())
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
pub(in crate::httpd)
async fn metrics(data: Data<Mutex<AppExporter>>) -> HttpResponse {
    debug!("Processing metrics request");

    let data = data.lock().expect("data lock");

    // Get the exporter from the state
    let exporter = &(data.exporter);

    // Exporter could fail.
    match exporter.collect() {
        Ok(o) => {
            HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, OPEN_METRICS_VERSION))
                .body(o)
        },
        Err(e) => {
            HttpResponse::InternalServerError()
                .insert_header(ContentType::plaintext())
                .body(format!("{e}"))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        dev::Service,
        test,
        web,
        App,
    };
    use actix_web::http::header::CONTENT_TYPE;
    use pretty_assertions::assert_eq;

    #[actix_web::test]
    async fn index_ok() {
        let state = AppState {
            index_page: "Test Body".into(),

            #[cfg(feature = "auth")]
            basic_auth_config: Default::default(),
        };

        let data = Data::new(state);

        let mut server = test::init_service(
            App::new()
                .app_data(data)
                .service(web::resource("/").to(index))
        ).await;

        let request  = test::TestRequest::get().uri("/").to_request();
        let response = server.call(request).await.unwrap();
        assert!(response.status().is_success());

        let headers = response.headers();
        let content_type = headers
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, ContentType::html().to_string());

        let request = test::TestRequest::get().uri("/").to_request();
        let body = test::call_and_read_body(&mut server, request).await;
        assert_eq!(body, "Test Body".as_bytes());
    }
}
