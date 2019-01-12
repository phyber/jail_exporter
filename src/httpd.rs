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
use askama::Template;
use log::{
    debug,
    info,
};
use std::net::SocketAddr;
use std::process::exit;

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

fn render_index_page(telemetry_path: &str) -> String {
    // Render the template
    debug!("Rendering index template");
    let index_template = IndexTemplate{
        telemetry_path: &telemetry_path,
    };

    match index_template.render() {
        Ok(i)  => i,
        Err(e) => {
            eprintln!("Failed to render index page template: {}", e);
            exit(1);
        },
    }
}

// Run the HTTP server at the given addr, serving telemetry on telemetry_path.
pub fn run(addr: &SocketAddr, telemetry_path: String) {
    let index_page = render_index_page(&telemetry_path);

    // Route handlers
    debug!("Registering HTTP app routes");
    let app = move || {
        let state = AppState{
            exporter:   jail_exporter::Metrics::new(),
            index_page: index_page.clone(),
        };

        actix_web::App::with_state(state)
            .resource("/", |r| r.method(http::Method::GET).f(index))
            .resource(&telemetry_path,
                      |r| r.method(http::Method::GET).f(metrics)
                      )
    };

    // Create the server
    debug!("Attempting to bind to: {}", addr);
    let server = match server::new(app).bind(addr) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("Couldn't bind to {}: {}", addr, e);
            exit(1);
        },
    };

    // Run it!
    info!("Starting HTTP server on {}", addr);
    server.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_render_index_page() {
        let path = "/a1b2c3";
        let rendered = render_index_page(&path);
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
