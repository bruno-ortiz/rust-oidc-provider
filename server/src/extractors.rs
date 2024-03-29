use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::{Extension, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use time::Duration;
use tower_cookies::{Cookie, Cookies, Key};

use oidc_core::session::SessionID;

pub const SESSION_KEY: &str = "oidc-session";

pub type ShareableSessionInner = Arc<Mutex<SessionInner>>;

#[derive(Debug)]
pub struct SessionInner {
    session: SessionID,
    duration: Option<Duration>,
}

impl SessionInner {
    pub async fn load(
        request: Request,
        key: Option<&Key>,
    ) -> Result<(Request, ShareableSessionInner), impl IntoResponse> {
        let cookies = request
            .extensions()
            .get::<Cookies>()
            .expect("tower-cookies must be configured");

        if let Some(key) = key {
            let signed_cookies = cookies.signed(key);
            let cookie = signed_cookies.get(SESSION_KEY);
            Self::parse_cookie(cookie.as_ref()).map(|si| (request, si))
        } else {
            let cookie = cookies.get(SESSION_KEY);
            Self::parse_cookie(cookie.as_ref()).map(|si| (request, si))
        }
    }

    fn parse_cookie(cookie: Option<&Cookie>) -> Result<ShareableSessionInner, impl IntoResponse> {
        match cookie {
            Some(cookie) => {
                let parsed_session = SessionID::from_str(cookie.value()).map_err(|err| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("invalid session id: {}", err),
                    )
                });
                match parsed_session {
                    Ok(session_id) => Ok(Arc::new(Mutex::new(SessionInner {
                        session: session_id,
                        duration: cookie.max_age(),
                    }))),
                    Err(err) => Err(err),
                }
            }
            None => Ok(Arc::new(Mutex::new(SessionInner {
                session: SessionID::new(),
                duration: None,
            }))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionHolder(ShareableSessionInner);

impl SessionHolder {
    pub fn new(inner: ShareableSessionInner) -> Self {
        Self(inner)
    }

    pub fn session_id(&self) -> SessionID {
        let inner = self.0.lock().unwrap();
        inner.session
    }

    pub fn duration(&self) -> Option<Duration> {
        let inner = self.0.lock().unwrap();
        inner.duration
    }

    pub fn set_duration(&self, new_duration: Duration) {
        let mut inner = self.0.lock().unwrap();
        inner.duration = Some(new_duration)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for SessionHolder
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Ok(Extension(session)) =
            Extension::<ShareableSessionInner>::from_request_parts(parts, state).await
        {
            Ok(SessionHolder(session))
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session manager layer not configured",
            ))
        }
    }
}
