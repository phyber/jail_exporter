//
// jail_exporter
//
// This module deals with httpd route handlers.
//
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use actix_web::HttpResponse;
use actix_web::http::header::ContentType;
use actix_web::web::{
    Bytes,
    Data,
};
use log::debug;
use std::sync::Mutex;
use super::{
    AppState,
    AppExporter,
};
use super::Collector;

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
pub(in crate::httpd) async fn index(data: Data<AppState>) -> HttpResponse {
    debug!("Displaying index page");

    let index = (&data.index_page).clone();
    let body = Bytes::from(index);

    HttpResponse::Ok()
        .insert_header(ContentType::html())
        .body(body)
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
pub(in crate::httpd) async fn metrics(data: Data<Mutex<AppExporter>>) -> HttpResponse {
    debug!("Processing metrics request");

    let data = data.lock().unwrap();

    // Get the exporter from the state
    let exporter = &(data.exporter);

    // Exporter could fail.
    match exporter.collect() {
        Ok(o) => {
            HttpResponse::Ok()
                .insert_header(ContentType::plaintext())
                .body(o)
        },
        Err(e) => {
            HttpResponse::InternalServerError()
                .insert_header(ContentType::plaintext())
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
    use actix_web::http::header::CONTENT_TYPE;
    use pretty_assertions::assert_eq;
    use std::str;

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
        let bytes = test::call_and_read_body(&mut server, request).await;
        let body = str::from_utf8(&bytes).unwrap();
        assert_eq!(body, "Test Body");
    }
}
