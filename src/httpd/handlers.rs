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

    let body = &(data.index_page);

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
    //use actix_service::Service;
    use actix_web::{
        http,
        test,
        web,
        //HttpMessage,
    };
    //use actix_http_test::TestServer;
    use pretty_assertions::assert_eq;
    use std::str;

    #[test]
    fn index_ok() {
        // Crate the test state
        let exporter = jail_exporter::Exporter::new();
        let state = AppState {
            exporter:   exporter.clone(),
            index_page: "Test Body".into(),
        };
        let data = Data::new(state);

        //let mut server = test::init_service(
        //    actix_web::App::new()
        //        .data(Data::new(state))
        //        .service(web::resource("/").to(index))
        //);

        // Create a test request
        //let req = test::TestRequest::with_uri("/").to_request();
        let req = test::TestRequest::with_uri("/").to_http_request();

        // Execute the request on the method we want to test and start
        // asserting things.
        //let resp = test::call_service(&mut server, req);
        let resp = test::block_on(index(data)).unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        let headers = resp.headers();
        let content_type = headers
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, TEXT_HTML_UTF_8);

        //let body = test::read_body(resp);
        let body = resp.body();
        //let body = str::from_utf8(&bytes).unwrap();
        //let body = resp.body().into_body();
        //let body = test::read_response(resp);
        assert_eq!(body, "Test Body");
    }

    //#[test]
    //fn index_ok() {
    //    let exporter = jail_exporter::Exporter::new();

    //    let mut server = TestServer::build_with_state(move || {
    //        AppState {
    //            exporter:   exporter.clone(),
    //            index_page: "Test Body".into(),
    //        }
    //    })
    //    .start(|app| {
    //        app.resource("/", |r| r.method(http::Method::GET).f(index));
    //    });

    //    let request = server.client(http::Method::GET, "/").finish().unwrap();
    //    let response = server.execute(request.send()).unwrap();
    //    assert_eq!(response.status(), http::StatusCode::OK);

    //    let headers = response.headers();
    //    let content_type = headers
    //        .get(CONTENT_TYPE)
    //        .unwrap()
    //        .to_str()
    //        .unwrap();
    //    assert_eq!(content_type, TEXT_HTML_UTF_8);

    //    let bytes = server.execute(response.body()).unwrap();
    //    let body = str::from_utf8(&bytes).unwrap();
    //    assert_eq!(body, "Test Body");
    //}
}
