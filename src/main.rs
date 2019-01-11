//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//
#![forbid(unsafe_code)]
use actix_web::{
    http,
    server,
    HttpRequest,
    HttpResponse,
};
use askama::Template;
use clap::{
    crate_authors,
    crate_description,
    crate_name,
    crate_version,
    ArgMatches,
};
use log::{
    debug,
    info,
};
use std::net::SocketAddr;
use std::process::exit;
use std::str;
use std::str::FromStr;

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

// Used as a validator for the argument parsing.
fn is_ipaddress(s: &str) -> Result<(), String> {
    let res = SocketAddr::from_str(&s);
    match res {
        Ok(_)  => Ok(()),
        Err(_) => Err(format!("'{}' is not a valid ADDR:PORT string", s)),
    }
}

// Checks for the availability of RACCT/RCTL in the kernel.
fn is_racct_rctl_available() -> bool {
    debug!("Checking RACCT/RCTL status");

    match rctl::State::check() {
        rctl::State::Disabled => {
            eprintln!(
                "RACCT/RCTL present, but disabled; enable using \
                 kern.racct.enable=1 tunable"
            );
            false
        },
        rctl::State::Enabled => true,
        rctl::State::Jailed => {
            eprintln!("RACCT/RCTL: Jail Exporter cannot run within a jail");
            false
        },
        rctl::State::NotPresent => {
            eprintln!(
                "RACCT/RCTL support not present in kernel; see rctl(8) \
                 for details"
            );
            false
        },
    }
}

// Parses the command line arguments and returns the matches.
fn parse_args<'a>() -> ArgMatches<'a> {
    debug!("Parsing command line arguments");

    clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            clap::Arg::with_name("WEB_LISTEN_ADDRESS")
                .env("JAIL_EXPORTER_WEB_LISTEN_ADDRESS")
                .hide_env_values(true)
                .long("web.listen-address")
                .value_name("[ADDR:PORT]")
                .help("Address on which to expose metrics and web interface.")
                .takes_value(true)
                .default_value("127.0.0.1:9452")
                .validator(|v| is_ipaddress(&v)),
        )
        .arg(
            clap::Arg::with_name("WEB_TELEMETRY_PATH")
                .env("JAIL_EXPORTER_WEB_TELEMETRY_PATH")
                .hide_env_values(true)
                .long("web.telemetry-path")
                .value_name("PATH")
                .help("Path under which to expose metrics.")
                .takes_value(true)
                .default_value("/metrics"),
        )
        .get_matches()
}

fn main() {
    env_logger::init();

    // First, check if RACCT/RCTL is available and if it's not, exit.
    if !is_racct_rctl_available() {
        exit(1);
    }

    // Parse the commandline arguments.
    let matches = parse_args();

    // This should always be fine, we've already validated it during arg
    // parsing.
    // However, we keep the expect as a last resort.
    let addr: SocketAddr = matches
        .value_of("WEB_LISTEN_ADDRESS")
        .unwrap()
        .parse()
        .expect("unable to parse socket address");
    debug!("web.listen-address: {}", addr);

    // Get the WEB_TELEMETRY_PATH and turn it into an owned string for moving
    // into the route handler below.
    // Unwrap here should be safe since we provide clap with a default value.
    let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH").unwrap();
    let telemetry_path = telemetry_path.to_owned();
    debug!("web.telemetry-path: {}", telemetry_path);

    // Render the template
    debug!("Rendering index template");
    let index_template = IndexTemplate{
        telemetry_path: &telemetry_path,
    };

    let index_page = match index_template.render() {
        Ok(i)  => i,
        Err(e) => {
            eprintln!("Failed to render index page template: {}", e);
            exit(1);
        },
    };

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
    server.run();
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_ipv4_with_port() {
        let addr = "127.0.0.1:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_ipv6_with_port() {
        let addr = "[::1]:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_ipv4_without_port() {
        let addr = "127.0.0.1";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_ipv6_without_port() {
        let addr = "[::1]";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_ip_address_no_ip() {
        let addr = "random string";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_render_index_page() {
        let path = "/a1b2c3";
        let template = IndexTemplate{
            telemetry_path: &path,
        };

        let rendered = template.render().unwrap();
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
