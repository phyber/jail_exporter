//
// jail_exporter
//
// This module deal httpd basic authentication.
//
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use super::AppState;
use crate::errors::ExporterError;
use actix_web::{
    dev::ServiceRequest,
    error::ErrorUnauthorized,
    web::Data,
    Error,
};
use actix_web_httpauth::extractors::basic::BasicAuth;
use log::debug;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;

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
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let config: Self = serde_yaml::from_reader(reader)?;

        config.validate()?;

        Ok(config)
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

// Validate HTTP Basic auth credentials.
// Usernames and passwords aren't checked in constant time.
pub async fn validate_credentials(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, Error> {
    debug!("Validating credentials");

    let state = req.app_data::<Data<AppState>>()
        .expect("Missing AppState")
        .get_ref();

    // Get the users from the config if they exist.
    let auth_config = &state.basic_auth_config;
    let auth_users = match &auth_config.basic_auth_users {
        Some(users) => users,
        None        => {
            // We shouldn't end up here, because the middleware should be
            // disabled if we have no users, but we handle it here anyway.
            debug!("No users defined in auth config, allowing access");
            return Ok(req);
        },
    };

    // Get the incoming user_id and check for an entry in the users hash
    let user_id = credentials.user_id().as_ref();
    if !auth_users.contains_key(user_id) {
        debug!("user_id doesn't match any configured user");
        return Err(ErrorUnauthorized("Unauthorized"));
    }

    // We know the user_id exists in the hash, get the hashed password for it.
    let hashed_password = &auth_users[user_id];

    // We need to get the reference to the Cow str to compare
    // passwords properly, so a little unwrapping is necessary
    let password = match credentials.password() {
        Some(password) => password.as_ref(),
        None           => return Err(ErrorUnauthorized("Unauthorized")),
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
        return Err(ErrorUnauthorized("Unauthorized"));
    };

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::httpd::{
        collector::Collector,
        errors::HttpdError,
    };

    use actix_web::{
        dev::Payload,
        test::TestRequest,
        FromRequest,
    };

    struct TestCollector;
    impl Collector for TestCollector {
        fn collect(&self) -> Result<Vec<u8>, HttpdError> {
            Ok("collector".as_bytes().to_vec())
        }
    }

    fn get_users_config() -> BasicAuthConfig {
        let mut users: HashMap<String, String> = HashMap::new();
        users.insert(
            "foo".into(),
            "$2b$04$nFPE4cwFjOFGUmdp.o2NTuh/blJDaEwikX1qoitVe144TsS2l5whS".into(),
        );

        BasicAuthConfig {
            basic_auth_users: Some(users),
        }
    }

    // Tests that errors are returned when config contains an invalid username
    #[actix_web::test]
    async fn basic_user_config_from_yaml_invalid() {
        let path = Path::new("test-data/config_invalid.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_err());
    }

    // Config is a null auth users entry.
    #[actix_web::test]
    async fn basic_user_config_from_yaml_null() {
        let path = Path::new("test-data/config_null.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }

    // Config consists of valid usernames
    #[actix_web::test]
    async fn basic_user_config_from_yaml_ok() {
        let path = Path::new("test-data/config_ok.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }

    #[actix_web::test]
    async fn validate_credentials_ok() {
        let exporter = Box::new(TestCollector);
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            exporter:          exporter,
            index_page:        "test".into(),
        };

        // HTTP request using Basic auth with username "foo" password "bar"
        let req = TestRequest::get()
            .data(data)
            .insert_header(("Authorization", "Basic Zm9vOmJhcg=="))
            .to_http_request();

        let credentials = BasicAuth::from_request(&req, &mut Payload::None)
            .await
            .unwrap();

        let req = ServiceRequest::from_request(req);
        let res = validate_credentials(req, credentials).await;

        assert!(res.is_ok());
    }

    #[actix_web::test]
    async fn validate_credentials_unauthorized() {
        let exporter = Box::new(TestCollector);
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            exporter:          exporter,
            index_page:        "test".into(),
        };

        // HTTP request using Basic auth with username "bad" password "password"
        let req = TestRequest::get()
            .data(data)
            .insert_header(("Authorization", "Basic YmFkOnBhc3N3b3Jk"))
            .to_http_request();

        let credentials = BasicAuth::from_request(&req, &mut Payload::None)
            .await
            .unwrap();

        let req = ServiceRequest::from_request(req);
        let res = validate_credentials(req, credentials).await;

        assert!(res.is_err());
    }
}
