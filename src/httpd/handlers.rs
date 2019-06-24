//
// jail_exporter
//
// This module deals with httpd route handlers.
//
#![forbid(unsafe_code)]
use actix_web::HttpResponse;
use actix_web::http::header::CONTENT_TYPE;
use actix_web::web::Data;
use log::debug;
use mime::{
    TEXT_HTML_UTF_8,
    TEXT_PLAIN_UTF_8,
};

use super::AppState;

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
pub(in crate::httpd) fn index(data: Data<AppState>) -> HttpResponse {
    debug!("Displaying index page");

    let body = &data.index_page;

    HttpResponse::Ok()
        .header(CONTENT_TYPE, TEXT_HTML_UTF_8)
        .body(body)
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
pub(in crate::httpd) fn metrics(data: Data<AppState>) -> HttpResponse {
    debug!("Processing metrics request");

    // Get the exporter from the state
    let exporter = &(data.exporter);

    // Exporter could fail.
    match exporter.export() {
        Ok(o) => {
            HttpResponse::Ok()
                .header(CONTENT_TYPE, TEXT_PLAIN_UTF_8)
                .body(o)
        },
        Err(e) => {
            HttpResponse::InternalServerError()
                .header(CONTENT_TYPE, TEXT_PLAIN_UTF_8)
                .body(format!("{}", e))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        web,
        App,
    };
    use actix_http::HttpService;
    use actix_http_test::TestServer;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    #[test]
    fn index_ok() {
        let exporter = jail_exporter::Exporter::new();
        let mut server = TestServer::new(move || {
            let state = AppState {
                exporter:   exporter.clone(),
                index_page: "Test Body".into(),
            };
            let data = Data::new(state);
            HttpService::new(
                App::new()
                .register_data(data)
                .service(web::resource("/").to(index))
            )
        });

        let request = server.get("/");
        let mut response = server.block_on(request.send()).unwrap();
        assert!(response.status().is_success());

        let headers = response.headers();
        let content_type = headers
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, TEXT_HTML_UTF_8);

        let bytes = server.block_on(response.body()).unwrap();
        assert_eq!(bytes, Bytes::from_static(b"Test Body").as_ref());
    }
}
