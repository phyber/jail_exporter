//
// jail_exporter
//
// This module deals with httpd related tasks.
//
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use actix_web::{
    middleware::Logger,
    web,
    HttpServer,
};
use log::{
    debug,
    info,
};

#[cfg(feature = "auth")]
use actix_web::middleware::Condition;

#[cfg(feature = "auth")]
use actix_web_httpauth::middleware::HttpAuthentication;

mod auth;
mod collector;
mod errors;
mod handlers;
mod templates;
use handlers::{
    index,
    metrics,
};
use templates::render_index_page;
pub use collector::Collector;
pub use errors::HttpdError;

// This AppState is used to pass the rendered index template to the index
// function.
pub(self) struct AppState {
    exporter:   Box<dyn Collector>,
    index_page: String,

    #[cfg(feature = "auth")]
    auth_password: Option<String>,

    #[cfg(feature = "auth")]
    auth_username: Option<String>,
}

// Used for the httpd builder
#[derive(Debug)]
pub struct Server {
    bind_address:   String,
    telemetry_path: String,

    #[cfg(feature = "auth")]
    auth_password: Option<String>,

    #[cfg(feature = "auth")]
    auth_username: Option<String>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind_address:   "127.0.0.1:9452".into(),
            telemetry_path: "/metrics".into(),

            #[cfg(feature = "auth")]
            auth_password: None,

            #[cfg(feature = "auth")]
            auth_username: None,
        }
    }
}

// Implements a builder pattern for configuring and running the http server.
impl Server {
    // Returns a new server instance.
    pub fn new() -> Self {
        Default::default()
    }

    #[cfg(feature = "auth")]
    // Sets the HTTP basic auth password
    pub fn auth_password(mut self, password: String) -> Self {
        debug!("Setting HTTP basic auth password to: {}", password);

        self.auth_password = Some(password);
        self
    }

    #[cfg(feature = "auth")]
    // Sets the HTTP basic auth username
    pub fn auth_username(mut self, username: String) -> Self {
        debug!("Setting HTTP basic auth username to: {}", username);

        self.auth_username = Some(username);
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
    pub async fn run<C: Collector>(self, exporter: Box<C>) -> Result<(), HttpdError>
    where C: 'static + Clone + Send + Sync {
        let bind_address   = self.bind_address;
        let index_page     = render_index_page(&self.telemetry_path)?;
        let telemetry_path = self.telemetry_path.clone();

        #[cfg(feature = "auth")]
        let auth_password = self.auth_password;

        #[cfg(feature = "auth")]
        let auth_username = self.auth_username;

        // Route handlers
        debug!("Registering HTTP app routes");
        let app = move || {
            // This state is shared between threads and allows us to pass
            // arbitrary items to request handlers.
            let state = AppState {
                exporter:   exporter.clone(),
                index_page: index_page.clone(),

                #[cfg(feature = "auth")]
                auth_password: auth_password.clone(),

                #[cfg(feature = "auth")]
                auth_username: auth_username.clone(),
            };

            // Order is important in the App config.
            let app = actix_web::App::new()
                .data(state)
                // Enable request logging
                .wrap(Logger::default());

            #[cfg(feature = "auth")]
            // Authentication
            let app = {
                // This boolean decides if the authentication middleware is
                // enabled in the wrap condition.
                let enable = auth_password.is_some() && auth_username.is_some();

                app.wrap(Condition::new(
                    enable,
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
