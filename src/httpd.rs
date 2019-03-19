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
};
use actix_web::middleware::Logger;
use log::{
    debug,
    info,
};

mod handlers;
use handlers::{
    index,
    metrics,
};
mod templates;
use templates::render_index_page;

// This AppState is used to pass the rendered index template to the index
// function.
pub(self) struct AppState {
    exporter:   jail_exporter::Exporter,
    index_page: String,
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
