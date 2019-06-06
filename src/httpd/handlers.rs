//
// jail_exporter
//
// This module deals with httpd route handlers.
//
#![forbid(unsafe_code)]
use actix_web::{
    HttpRequest,
    HttpResponse,
};
use actix_web::http::header::CONTENT_TYPE;
use log::debug;
use mime::{
    TEXT_HTML_UTF_8,
    TEXT_PLAIN_UTF_8,
};

use super::AppState;

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
pub(in crate::httpd) fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    debug!("Displaying index page");

    let body = &(req.state().index_page);

    HttpResponse::Ok()
        .header(CONTENT_TYPE, TEXT_HTML_UTF_8)
        .body(body)
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
pub(in crate::httpd) fn metrics(req: &HttpRequest<AppState>) -> HttpResponse {
    debug!("Processing metrics request");

    // Get the exporter from the state
    let exporter = &(req.state().exporter);

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
        http,
        test,
        HttpMessage,
    };
    use pretty_assertions::assert_eq;
    use std::str;

    #[test]
    fn index_ok() {
        let exporter = jail_exporter::Exporter::new();

        let mut server = test::TestServer::build_with_state(move || {
            AppState {
                exporter:   exporter.clone(),
                index_page: "Test Body".into(),
            }
        })
        .start(|app| {
            app.resource("/", |r| r.method(http::Method::GET).f(index));
        });

        let request = server.client(http::Method::GET, "/").finish().unwrap();
        let response = server.execute(request.send()).unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let headers = response.headers();
        let content_type = headers
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, TEXT_HTML_UTF_8);

        let bytes = server.execute(response.body()).unwrap();
        let body = str::from_utf8(&bytes).unwrap();
        assert_eq!(body, "Test Body");
    }
}
