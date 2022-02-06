use std::future::{ready, Ready};

use actix_session::Session;
use actix_web::dev::Payload;
use actix_web::{error, Error, FromRequest, HttpRequest};

use oidc_core::session::SessionID;

const SESSION_KEY: &str = "oidc-session";

pub struct SessionHolder(pub SessionID);

impl FromRequest for SessionHolder {
    type Error = Error;
    type Future = Ready<Result<SessionHolder, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let session = req
            .app_data::<Session>()
            .expect("actix-session must be configured");
        let raw_session = session.get::<String>(SESSION_KEY);
        match raw_session {
            Ok(session) => {
                let session_id = if let Some(session) = session {
                    let parsed_session = SessionID::from_string(session).map_err(|err| {
                        error::ErrorBadRequest(format!("invalid session id: {}", err))
                    });
                    match parsed_session {
                        Ok(session_id) => session_id,
                        Err(err) => return ready(Err(err)),
                    }
                } else {
                    SessionID::new()
                };
                ready(Ok(SessionHolder(session_id)))
            }
            Err(err) => ready(Err(err)),
        }
    }
}
