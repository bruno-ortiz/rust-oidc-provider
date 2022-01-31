use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use actix_session::Session;
use actix_web::dev::Payload;
use actix_web::{error, Error, FromRequest, HttpRequest};
use uuid::{Error as UuidError, Uuid};

use oidc_types::subject::Subject;

const SESSION_KEY: &str = "oidc-session";

pub enum UserSession {
    Authenticated(SessionID, Subject),
    NotAuthenticated(SessionID),
}

pub struct SessionID(Uuid);

impl SessionID {
    fn new() -> Self {
        SessionID(Uuid::new_v4())
    }

    fn from(id: String) -> Result<Self, UuidError> {
        let session_id = Uuid::from_str(&id)?;
        Ok(SessionID(session_id))
    }
}

impl FromRequest for UserSession {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let session = req
            .app_data::<Session>()
            .expect("actix-session must be configured");
        let session_id = session.get::<String>(SESSION_KEY);
        match session_id {
            Ok(session) => {
                if let Some(session) = session {
                    let subject = Subject::new("42"); //todo: implement
                    let session_id = SessionID::from(session).map_err(|err| {
                        error::ErrorBadRequest(format!("invalid session id: {}", err))
                    });
                    Box::pin(async move { Ok(UserSession::Authenticated(session_id?, subject)) })
                } else {
                    Box::pin(async move { Ok(UserSession::NotAuthenticated(SessionID::new())) })
                }
            }
            Err(err) => Box::pin(async move { Err(err) }),
        }
    }
}
