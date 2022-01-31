use std::future::Future;
use std::pin::Pin;

use actix_web::dev::Payload;
use actix_web::{Error, FromRequest, HttpRequest};
use uuid::Uuid;

use oidc_types::subject::Subject;

enum UserSession {
    Authenticated(SessionID, Subject),
    NotAuthenticated(SessionID),
}

struct SessionID(Uuid);

impl SessionID {
    fn new() -> Self {
        SessionID(Uuid::new_v4())
    }
}

impl FromRequest for UserSession {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        Box::pin(async move { Ok(UserSession::NotAuthenticated(SessionID::new())) })
    }
}
