//
// jail_exporter
//
// This module deals with httpd route handlers.
//
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use actix_web::HttpResponse;
use actix_web::http::header::CONTENT_TYPE;
use actix_web::web::{
    self,
    Data,
};
use log::debug;
use mime::{
    TEXT_HTML_UTF_8,
    TEXT_PLAIN_UTF_8,
};
use super::AppState;

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
pub(in crate::httpd) async fn index(data: Data<AppState>) -> HttpResponse {
    debug!("Displaying index page");

    let index = (&data.index_page).to_owned();
    let body = web::Bytes::from(index);

    HttpResponse::Ok()
        .insert_header((CONTENT_TYPE, TEXT_HTML_UTF_8))
        .body(body)
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
pub(in crate::httpd) async fn metrics(data: Data<AppState>) -> HttpResponse {
    debug!("Processing metrics request");

    // Get the exporter from the state
    let exporter = &(data.exporter);

    // Exporter could fail.
    match exporter.collect() {
        Ok(o) => {
            HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, TEXT_PLAIN_UTF_8))
                .body(o)
        },
        Err(e) => {
            HttpResponse::InternalServerError()
                .insert_header((CONTENT_TYPE, TEXT_PLAIN_UTF_8))
                .body(format!("{}", e))
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
    use crate::exporter::Exporter;
    use pretty_assertions::assert_eq;
    use std::str;

    #[actix_web::test]
    async fn index_ok() {
        let exporter = Box::new(Exporter::new());

        let state = AppState {
            exporter:   exporter.clone(),
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
        assert_eq!(content_type, TEXT_HTML_UTF_8);

        let request = test::TestRequest::get().uri("/").to_request();
        let bytes = test::call_and_read_body(&mut server, request).await;
        let body = str::from_utf8(&bytes).unwrap();
        assert_eq!(body, "Test Body");
    }
}
