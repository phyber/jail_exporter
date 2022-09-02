//
// jail_exporter
//
// This module deals with httpd related tasks.
//
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use actix_web::HttpServer;
use actix_web::middleware::Logger;
use actix_web::web::{
    self,
    Data,
};
use log::{
    debug,
    info,
};
use std::sync::Mutex;

#[cfg(feature = "auth")]
use actix_web::middleware::Condition;

#[cfg(feature = "auth")]
use actix_web_httpauth::middleware::HttpAuthentication;

#[cfg(feature = "auth")]
pub mod auth;

mod collector;
mod errors;
mod handlers;
mod templates;

#[cfg(feature = "auth")]
pub use auth::BasicAuthConfig;

use handlers::{
    index,
    metrics,
};
use templates::render_index_page;
pub use collector::Collector;
pub use errors::HttpdError;
use super::Exporter;

// This AppState is used to pass the rendered index template to the index
// function.
#[derive(Clone)]
pub(self) struct AppState {
    //exporter:   Box<dyn Collector>,
    index_page: String,

    #[cfg(feature = "auth")]
    basic_auth_config: BasicAuthConfig,
}

struct AppExporter {
    exporter: Exporter,
}

// Used for the httpd builder
#[derive(Debug)]
pub struct Server {
    bind_address:   String,
    telemetry_path: String,

    #[cfg(feature = "auth")]
    basic_auth_config: Option<BasicAuthConfig>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind_address:   "127.0.0.1:9452".into(),
            telemetry_path: "/metrics".into(),

            #[cfg(feature = "auth")]
            basic_auth_config: None,
        }
    }
}

// Implements a builder pattern for configuring and running the http server.
impl Server {
    // Returns a new server instance.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "auth")]
    // Set the HTTP Basic Auth configuration
    pub fn auth_config(mut self, config: BasicAuthConfig) -> Self {
        debug!("Setting HTTP basic auth config");

        self.basic_auth_config = Some(config);
        self
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
    pub async fn run(self, exporter: Exporter) -> Result<(), HttpdError> {
        let bind_address   = self.bind_address;
        let index_page     = render_index_page(&self.telemetry_path)?;
        let telemetry_path = self.telemetry_path.clone();

        #[cfg(feature = "auth")]
        // Unwrap the config if we have one, otherwise use a default.
        let basic_auth_config = match self.basic_auth_config {
            Some(config) => config,
            None         => BasicAuthConfig::default(),
        };

        // These states are shared between threads and allows us to pass
        // arbitrary items to request handlers.
        let app_exporter = AppExporter {
            exporter: exporter,
        };

        let app_exporter = Data::new(Mutex::new(app_exporter));

        let state = AppState {
            index_page: index_page.clone(),

            #[cfg(feature = "auth")]
            basic_auth_config: basic_auth_config.clone(),
        };

        let state = Data::new(state);

        // Route handlers
        debug!("Creating HTTP server app");
        let app = move || {
            // Order is important in the App config.
            let app = actix_web::App::new()
                .app_data(app_exporter.clone())
                .app_data(state.clone())
                // Enable request logging
                .wrap(Logger::default());

            #[cfg(feature = "auth")]
            // Authentication
            let app = {
                // Only enable the authentication if there are some users to
                // check.
                app.wrap(Condition::new(
                    basic_auth_config.basic_auth_users.is_some(),
                    HttpAuthentication::basic(auth::validate_credentials),
                ))
            };

            // Finally add routes
            app
                // Root of HTTP server. Provides a basic index page and
                // link to the metrics page.
                .route("/", web::get().to(index))
                // Path serving up the metrics.
                .route(&telemetry_path, web::get().to(metrics))
        };


        // Create the server
        debug!("Attempting to bind to: {}", bind_address);
        let server = HttpServer::new(app)
        .bind(&bind_address)
        .map_err(|e| {
            HttpdError::BindAddress(format!("{}: {}", bind_address, e))
        })?;

        // Run it!
        info!("Starting HTTP server on {}", bind_address);
        server.run().await?;

        Ok(())
    }
}
