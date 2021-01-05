//
// jail_exporter
//
// This module deal httpd basic authentication.
//
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use super::AppState;
use log::debug;
use actix_web::{
    dev::ServiceRequest,
    error::ErrorUnauthorized,
    web::Data,
    Error,
};
use actix_web_httpauth::extractors::basic::BasicAuth;

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

    // These derefs give us an Option<&str> instead of the real
    // Option<String>, allowing us to compare to the Cow<&str>
    // easily later on.
    let auth_password = state.auth_password.as_deref();
    let auth_username = state.auth_username.as_deref();

    // If the state password or username are None, no
    // authentication was setup, and we can simply return.
    if auth_password.is_none() || auth_username.is_none() {
        debug!("No username or password in AppState, allowing access");
        return Ok(req);
    }

    // Username comparson is simple.
    let user_id = credentials.user_id().as_ref();
    if Some(user_id) != auth_username {
        debug!("user_id doesn't match auth_username, denying access");
        return Err(ErrorUnauthorized("Unauthorized"));
    };

    // We need to get the reference to the Cow str to compare
    // passwords properly, so a little unwrapping is necessary
    let password = match credentials.password() {
        Some(password) => Some(password.as_ref()),
        None           => None,
    };

    if password != auth_password {
        debug!("password doesn't match auth_password, denying access");
        return Err(ErrorUnauthorized("Unauthorized"));
    };

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "auth")]
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

    #[cfg(feature = "auth")]
    #[actix_rt::test]
    async fn validate_credentials_ok() {
        let exporter = Box::new(TestCollector);

        let data = AppState {
            auth_password: Some("bar".into()),
            auth_username: Some("foo".into()),
            exporter:      exporter,
            index_page:    "test".into(),
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

    #[cfg(feature = "auth")]
    #[actix_rt::test]
    async fn validate_credentials_unauthorized() {
        let exporter = Box::new(TestCollector);

        let data = AppState {
            auth_password: Some("bar".into()),
            auth_username: Some("foo".into()),
            exporter:      exporter,
            index_page:    "test".into(),
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
