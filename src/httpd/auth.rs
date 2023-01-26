// auth: This module deal httpd basic authentication.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use super::AppState;
use crate::errors::ExporterError;
use axum::extract::State;
use axum::http::{
    Request,
    StatusCode,
};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use log::debug;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

// Invalid username characters as defined in RFC7617.
// 0x00 - 0x1f / 0x7f / :
// These are split up to hopefully make the set easier for a human to validate
const INVALID_USERNAME_CHARS: &[char] = &[
    // 0x00 - 0x09
    '\u{00}', '\u{01}', '\u{02}', '\u{03}', '\u{04}', '\u{05}',
    '\u{06}', '\u{07}', '\u{08}', '\u{09}',
    // 0x0a - 0x0f
    '\u{0a}', '\u{0b}', '\u{0c}', '\u{0d}', '\u{0e}', '\u{0f}',
    // 0x10 - 0x19
    '\u{10}', '\u{11}', '\u{12}', '\u{13}', '\u{14}', '\u{15}',
    '\u{16}', '\u{17}', '\u{18}', '\u{19}',
    // 0x1a - 0x1f
    '\u{1a}', '\u{1b}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}',
    // 0x7f
    '\u{7f}',
    // Colon
    ':',
];

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BasicAuthConfig {
    pub basic_auth_users: Option<HashMap<String, String>>,
}

impl BasicAuthConfig {
    // Loads a YAML config from the given path returning the BasicAuthConfig
    pub fn from_yaml(path: &Path) -> Result<Self, ExporterError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let config: Self = serde_yaml::from_reader(reader)?;

        config.validate()?;

        Ok(config)
    }

    // Returns a boolean indicating if we have any users configured.
    pub fn has_users(&self) -> bool {
        self.basic_auth_users.is_some()
    }

    // Validates that usernames don't contain invalid characters.
    fn validate(&self) -> Result<(), ExporterError> {
        // Not having users is perfectly valid.
        let users = match &self.basic_auth_users {
            None        => return Ok(()),
            Some(users) => users,
        };

        for (username, hashed_password) in users {
            // A username is invalid if it contains any characters from the
            // INVALID_USERNAME_CHARS const.
            let invalid_username = username
                .chars()
                .any(|c| INVALID_USERNAME_CHARS.contains(&c));

            if invalid_username {
                let err = ExporterError::InvalidUsername(username.into());
                return Err(err);
            }

            if let Err(err) = bcrypt::HashParts::from_str(hashed_password) {
                let msg = format!(
                    "bcrypt error '{}' when validating user {}",
                    err,
                    username,
                );

                let err = ExporterError::BcryptValidationError(msg);
                return Err(err);
            }
        }

        Ok(())
    }
}

// Decode a Basic base64 into a username and password
fn decode(data: &str) -> Result<(String, Option<String>), StatusCode> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let decoded = String::from_utf8(decoded)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let split = decoded.split_once(':');

    match split {
        Some((username, password)) => {
            Ok((username.to_string(), Some(password.to_string())))
        },
        _ => Ok((decoded, None)),
    }
}

// Validate HTTP Basic auth credentials.
// Usernames and passwords aren't checked in constant time.
pub async fn validate_credentials<B>(
    State(state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    debug!("Validating credentials");

    // Get the user database out of the AppState
    // If no users are in the database, authentication is disabled and
    // requests are allowed through.
    let users = match &state.basic_auth_config.basic_auth_users {
        Some(users) => users,
        None        => return Ok(next.run(req).await),
    };

    // If we have users, start working on authenticating the request.
    // Get Authorization header
    let auth_header = req.headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    // Return the header if present, otherwise unauthorized.
    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    }
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Extract the username and password out of the header
    let split = auth_header.split_once(' ');
    let decoded = match split {
        Some((type_, contents)) if type_ == "Basic" => {
            decode(contents)?
        },
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Get the incoming user_id and check for an entry in the users hash
    let user_id = &decoded.0;

    if !users.contains_key(user_id) {
        debug!("user_id doesn't match any configured user");

        return Err(StatusCode::UNAUTHORIZED);
    }

    // We know the user_id exists in the hash, get the hashed password for it.
    let hashed_password = &users[user_id];

    // We need to get the reference to the Cow str to compare
    // passwords properly, so a little unwrapping is necessary
    let password = decoded.1;
    let password = match password {
        Some(password) => password,
        None           => {
            return Err(StatusCode::UNAUTHORIZED);
        },
    };

    let validated = match bcrypt::verify(password, hashed_password) {
        Ok(b)  => b,
        Err(e) => {
            // We can't easily deal with the original error here, so log it and
            // simply don't validate the user.
            debug!("Couldn't verify password, bcrypt error: {}", e);
            false
        },
    };

    if !validated {
        debug!("password doesn't match auth_password, denying access");

        return Err(StatusCode::UNAUTHORIZED);
    };

    let response = next.run(req).await;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{
            self,
            Request,
        },
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/", get(|| async { "Test" }))
            .route_layer(
                middleware::from_fn_with_state(
                    state,
                    validate_credentials,
                ),
            )
    }

    fn get_users_config() -> BasicAuthConfig {
        let users = HashMap::from([(
            "foo".to_string(),
            "$2b$04$nFPE4cwFjOFGUmdp.o2NTuh/blJDaEwikX1qoitVe144TsS2l5whS".to_string(),
        )]);

        BasicAuthConfig {
            basic_auth_users: Some(users),
        }
    }

    // Tests that errors are returned when config contains an invalid username
    #[test]
    fn basic_user_config_from_yaml_invalid() {
        let path = Path::new("test-data/config_invalid.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_err());
    }

    // Config is a null auth users entry.
    #[test]
    fn basic_user_config_from_yaml_null() {
        let path = Path::new("test-data/config_null.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }

    // Config consists of valid usernames
    #[test]
    fn basic_user_config_from_yaml_ok() {
        let path = Path::new("test-data/config_ok.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }

    #[tokio::test]
    async fn validate_credentials_ok() {
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request using Basic auth with username "foo" password "bar"
        let req = Request::builder()
            .uri("/")
            .header(http::header::AUTHORIZATION, "Basic Zm9vOmJhcg==")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn validate_credentials_unauthorized() {
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request using Basic auth with username "bad" password "password"
        let req = Request::builder()
            .uri("/")
            .header(http::header::AUTHORIZATION, "Basic YmFkOnBhc3N3b3Jk")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED)
    }
}
