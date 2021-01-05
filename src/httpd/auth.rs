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

// Invalid username characters as defined in RFC7617
const INVALID_USERNAME_CHARS: &[char] = &[':'];

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BasicAuthConfig {
    pub basic_auth_users: Option<HashMap<String, String>>,
}

impl BasicAuthConfig {
    // Loads a YAML config from the given path returning the BasicAuthConfig
    pub fn from_yaml(path: &str) -> Result<Self, ExporterError> {
        let path = Path::new(&path);
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

            if let Err(err) = bcrypt::HashParts::from_str(&hashed_password) {
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
        test,
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
    #[test]
    fn basic_user_config_from_yaml_invalid() {
        let path = "test-data/config_invalid.yaml";
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_err());
    }

    // Config consists of valid usernames
    #[test]
    fn basic_user_config_from_yaml_ok() {
        let path = "test-data/config_ok.yaml";
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }

    #[actix_rt::test]
    async fn validate_credentials_ok() {
        let exporter = Box::new(TestCollector);
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            exporter:          exporter,
            index_page:        "test".into(),
        };

        // HTTP request using Basic auth with username "foo" password "bar"
        let req = test::TestRequest::get()
            .data(data)
            .header("Authorization", "Basic Zm9vOmJhcg==")
            .to_http_request();

        let credentials = BasicAuth::from_request(&req, &mut Payload::None)
            .await
            .unwrap();

        let req = ServiceRequest::from_request(req).unwrap();
        let res = validate_credentials(req, credentials).await;

        assert!(res.is_ok());
    }

    #[actix_rt::test]
    async fn validate_credentials_unauthorized() {
        let exporter = Box::new(TestCollector);
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            exporter:          exporter,
            index_page:        "test".into(),
        };

        // HTTP request using Basic auth with username "bad" password "password"
        let req = test::TestRequest::get()
            .data(data)
            .header("Authorization", "Basic YmFkOnBhc3N3b3Jk")
            .to_http_request();

        let credentials = BasicAuth::from_request(&req, &mut Payload::None)
            .await
            .unwrap();

        let req = ServiceRequest::from_request(req).unwrap();
        let res = validate_credentials(req, credentials).await;

        assert!(res.is_err());
    }
}
