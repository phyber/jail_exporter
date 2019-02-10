//
// jail_exporter
//
// This module deals with httpd related tasks.
//
#![forbid(unsafe_code)]
use crate::errors::Error;
use actix_web::{
    http,
    server,
    HttpRequest,
    HttpResponse,
};
use actix_web::http::header::CONTENT_TYPE;
use actix_web::middleware::Logger;
use askama::Template;
use log::{
    debug,
    info,
};

// This AppState is used to pass the rendered index template to the index
// function.
struct AppState {
    exporter:   jail_exporter::Exporter,
    index_page: String,
}

// Template for the index served at /. Useful for people connecting to the
// exporter via their browser.
// Escaping is disabled since we're passing a path and don't want the / to be
// escaped.
#[derive(Template)]
#[template(path = "index.html", escape = "none")]
struct IndexTemplate<'a> {
    telemetry_path: &'a str,
}

// Used for the httpd builder
#[derive(Debug)]
pub struct Server {
    bind_address:   String,
    telemetry_path: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind_address:   "127.0.0.1:9452".into(),
            telemetry_path: "/metrics".into(),
        }
    }
}

// Implements a builder pattern for configuring and running the http server.
impl Server {
    // Returns a new server instance.
    pub fn new() -> Self {
        Default::default()
    }

    // Sets the bind_address of the server.
    pub fn bind_address(mut self, bind_address: String) -> Self {
        debug!("Setting server bind_address to: {}", bind_address);

        self.bind_address = bind_address;
        self
    }

    // Sets the telemetry path for the metrics.
    pub fn telemetry_path(mut self, telemetry_path: String) -> Self {
        debug!("Setting server telemetry_path to: {}", telemetry_path);

        self.telemetry_path = telemetry_path;
        self
    }

    // Run the HTTP server.
    pub fn run(self) -> Result<(), Error> {
        let bind_address   = self.bind_address;
        let exporter       = jail_exporter::Exporter::new();
        let index_page     = render_index_page(&self.telemetry_path)?;
        let telemetry_path = self.telemetry_path.clone();

        // Route handlers
        debug!("Registering HTTP app routes");
        let app = move || {
            // This state is shared between threads and allows us to pass
            // arbitrary items to request handlers.
            let state = AppState {
                exporter:   exporter.clone(),
                index_page: index_page.clone(),
            };

            actix_web::App::with_state(state)
                // Enable request logging
                .middleware(Logger::default())

                // Root of HTTP server. Provides a basic index page and link to
                // the metrics page.
                .resource("/", |r| r.method(http::Method::GET).f(index))

                // Path serving up the metrics.
                .resource(&telemetry_path, |r| {
                    r.method(http::Method::GET).f(metrics)
                })
        };

        // Create the server
        debug!("Attempting to bind to: {}", bind_address);
        let server = match server::new(app).bind(&bind_address) {
            Ok(s)  => Ok(s),
            Err(e) => {
                Err(Error::BindAddress(format!("{}: {}", bind_address, e)))
            },
        }?;

        // Run it!
        info!("Starting HTTP server on {}", bind_address);
        server.run();

        Ok(())
    }
}

// Displays the index page. This is a page which simply links to the actual
// telemetry path.
fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    debug!("Displaying index page");

    let body = &(req.state().index_page);

    HttpResponse::Ok()
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body)
}

// Returns a HttpResponse containing the Prometheus Exporter output, or an
// InternalServerError if things fail for some reason.
fn metrics(req: &HttpRequest<AppState>) -> HttpResponse {
    debug!("Processing metrics request");

    // Get the exporter from the state
    let exporter = &(req.state().exporter);

    // Exporter could fail.
    match exporter.export() {
        Ok(o) => {
            HttpResponse::Ok()
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(o)
        },
        Err(e) => {
            HttpResponse::InternalServerError()
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(format!("{}", e))
        },
    }
}

// Renders the index page template.
fn render_index_page(telemetry_path: &str) -> Result<String, Error> {
    debug!("Rendering index template");

    let index_template = IndexTemplate {
        telemetry_path: &telemetry_path,
    };

    match index_template.render() {
        Ok(i)  => Ok(i),
        Err(e) => Err(Error::RenderTemplate(format!("index: {}", e))),
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
    use indoc::indoc;
    use std::str;

    #[test]
    fn test_index_ok() {
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
        let content_type = headers.get(CONTENT_TYPE).unwrap();
        assert_eq!(content_type, "text/html; charset=utf-8");

        let bytes = server.execute(response.body()).unwrap();
        let body = str::from_utf8(&bytes).unwrap();
        assert_eq!(body, "Test Body");
    }

    #[test]
    fn test_render_index_page() {
        let path = "/a1b2c3";
        let rendered = render_index_page(&path).unwrap();
        let ok = indoc!(
            r#"
            <!DOCTYPE html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>Jail Exporter</title>
                </head>
                <body>
                    <h1>Jail Exporter</h1>
                    <p><a href="/a1b2c3">Metrics</a></p>
                </body>
            </html>"#
        );
        assert_eq!(rendered, ok);
    }
}
