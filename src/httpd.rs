//
// jail_exporter
//
// This module deals with httpd related tasks.
//
#![forbid(unsafe_code)]
use actix_web::{
    http,
    server,
    HttpRequest,
    HttpResponse,
};
use actix_web::middleware::Logger;
use askama::Template;
use crate::errors::Error;
use log::{
    debug,
    info,
};
use std::net::SocketAddr;

// This AppState is used to pass the rendered index template to the index
// function.
struct AppState {
    exporter:   jail_exporter::Metrics,
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
    bind_address:   SocketAddr,
    telemetry_path: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind_address:   "127.0.0.1:9452".parse().unwrap(),
            telemetry_path: "/metrics".into(),
        }
    }
}

// Implements a builder pattern for configuring and running the http server.
impl Server {
    // Returns a new server instance.
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    // Sets the bind_address of the server.
    pub fn bind_address(&mut self, bind_address: String)
    -> Result<&mut Self, Error> {
        debug!("Setting server bind_address to: {}", bind_address);

        self.bind_address = match bind_address.parse() {
            Ok(ba) => Ok(ba),
            Err(e) => Err(
                Error::SocketAddr(format!("{}: {}", bind_address, e))
            ),
        }?;
        Ok(self)
    }

    // Sets the telemetry path for the metrics.
    pub fn telemetry_path(&mut self, telemetry_path: String) -> &mut Self {
        debug!("Setting server telemetry_path to: {}", telemetry_path);

        self.telemetry_path = telemetry_path;
        self
    }

    // Run the HTTP server.
    pub fn run(&self) -> Result<(), Error> {
        let exporter       = jail_exporter::Metrics::new();
        let index_page     = render_index_page(&self.telemetry_path)?;
        let telemetry_path = self.telemetry_path.clone();

        // Route handlers
        debug!("Registering HTTP app routes");
        let app = move || {
            // This state is shared between threads and allows us to pass
            // arbitrary items to request handlers.
            let state = AppState{
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
                .resource(&telemetry_path,
                          |r| r.method(http::Method::GET).f(metrics)
                          )
        };

        // Create the server
        debug!("Attempting to bind to: {}", self.bind_address);
        let server = match server::new(app).bind(self.bind_address) {
            Ok(s)  => Ok(s),
            Err(e) => {
                Err(Error::BindAddress(
                    format!("{}: {}", self.bind_address, e)
                ))
            },
        }?;

        // Run it!
        info!("Starting HTTP server on {}", self.bind_address);
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
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body)
}

// Returns a warp Reply containing the Prometheus Exporter output, or a
// Rejection if things fail for some reason.
fn metrics(req: &HttpRequest<AppState>) -> HttpResponse {
    debug!("Processing metrics request");

    // Get exporter output
    let exporter = &(req.state().exporter);
    let output = exporter.export();

    // Send it out
    HttpResponse::Ok()
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(output)
}

fn render_index_page(telemetry_path: &str) -> Result<String, Error> {
    // Render the template
    debug!("Rendering index template");
    let index_template = IndexTemplate{
        telemetry_path: &telemetry_path,
    };

    match index_template.render() {
        Ok(i)  => Ok(i),
        Err(e) => {
            Err(Error::RenderTemplate(
                format!("index: {}", e)
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

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
            </html>"#);
        assert_eq!(rendered, ok);
    }
}
