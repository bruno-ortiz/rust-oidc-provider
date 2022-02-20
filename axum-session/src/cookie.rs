//! Cookie based sessions. See docs for [`CookieSession`].

use std::collections::HashMap;
use std::str::Utf8Error;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::headers::HeaderValue;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::StatusCode;
use cookie::{Cookie, CookieJar, Key, ParseError, SameSite};
use futures::future::BoxFuture;
use hyper::header::InvalidHeaderValue;
use hyper::Body;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tower::Service;

use crate::{IntoResponse, Request, Response, Session, SessionInner, SessionStatus};

/// Errors that can occur during handling cookie session
#[derive(Debug, Error)]
pub enum CookieSessionError {
    /// Size of the serialized session is greater than 4000 bytes.
    #[error("Size of the serialized session is greater than 4000 bytes.")]
    Overflow,

    /// Fail to serialize session.
    #[error("Fail to serialize session")]
    Serialize,
    #[error("Invalid header")]
    InvalidHeader(#[from] InvalidHeaderValue),
}

impl IntoResponse for CookieSessionError {
    fn into_response(self) -> Response {
        let mut res = self.to_string().into_response();
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        res
    }
}

#[derive(Copy, Clone)]
enum CookieSecurity {
    Signed,
    Private,
}

#[derive(Clone)]
struct CookieSessionInner {
    key: Key,
    security: CookieSecurity,
    name: String,
    path: String,
    domain: Option<String>,
    lazy: bool,
    secure: bool,
    http_only: bool,
    max_age: Option<Duration>,
    expires_in: Option<Duration>,
    same_site: Option<SameSite>,
}

impl CookieSessionInner {
    fn new(key: &[u8], security: CookieSecurity) -> CookieSessionInner {
        CookieSessionInner {
            security,
            key: Key::derive_from(key),
            name: "axum-session".to_owned(),
            path: "/".to_owned(),
            domain: None,
            lazy: false,
            secure: true,
            http_only: true,
            max_age: None,
            expires_in: None,
            same_site: None,
        }
    }

    fn set_cookie<B>(
        &self,
        res: &mut Response<B>,
        state: impl Iterator<Item = (String, String)>,
    ) -> Result<(), CookieSessionError> {
        let state: HashMap<String, String> = state.collect();
        if self.lazy && state.is_empty() {
            return Ok(());
        }

        let value = serde_json::to_string(&state).map_err(|_err| CookieSessionError::Serialize)?;

        if value.len() > 4064 {
            return Err(CookieSessionError::Overflow);
        }

        let mut cookie = Cookie::new(self.name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        if let Some(expires_in) = self.expires_in {
            cookie.set_expires(OffsetDateTime::now_utc() + expires_in);
        }

        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age);
        }

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }

        let mut jar = CookieJar::new();

        match self.security {
            CookieSecurity::Signed => jar.signed_mut(&self.key).add(cookie),
            CookieSecurity::Private => jar.private_mut(&self.key).add(cookie),
        }

        for cookie in jar.delta() {
            let val = HeaderValue::from_str(&cookie.encoded().to_string())
                .map_err(CookieSessionError::InvalidHeader)?;
            res.headers_mut().append(SET_COOKIE, val);
        }

        Ok(())
    }

    /// invalidates session cookie
    fn remove_cookie<B>(&self, res: &mut Response<B>) -> Result<(), CookieSessionError> {
        let mut cookie = Cookie::named(self.name.clone());
        cookie.set_path(self.path.clone());
        cookie.set_value("");
        cookie.set_max_age(Duration::ZERO);
        cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));

        let val = HeaderValue::from_str(&cookie.to_string())
            .map_err(CookieSessionError::InvalidHeader)?;
        res.headers_mut().append(SET_COOKIE, val);

        Ok(())
    }

    fn load(&self, req: &mut Request<Body>) -> (bool, HashMap<String, String>) {
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.lock().unwrap().iter() {
                if cookie.name() == self.name {
                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = match self.security {
                        CookieSecurity::Signed => jar.signed(&self.key).get(&self.name),
                        CookieSecurity::Private => jar.private(&self.key).get(&self.name),
                    };

                    if let Some(cookie) = cookie_opt {
                        if let Ok(val) = serde_json::from_str(cookie.value()) {
                            return (false, val);
                        }
                    }
                }
            }
        }

        (true, HashMap::new())
    }
}

#[derive(Debug, Error)]
enum CookieParseError {
    #[error(transparent)]
    Utf8Err(#[from] Utf8Error),
    #[error(transparent)]
    ParseError(#[from] ParseError),
}

trait RequestPartsExt {
    fn cookies(&mut self) -> Result<Arc<Mutex<Vec<Cookie<'static>>>>, CookieParseError>;
}

impl<B> RequestPartsExt for Request<B> {
    fn cookies(&mut self) -> Result<Arc<Mutex<Vec<Cookie<'static>>>>, CookieParseError> {
        if self
            .extensions()
            .get::<Arc<Mutex<Vec<Cookie<'static>>>>>()
            .is_none()
        {
            let cookies = Arc::new(Mutex::new(Vec::new()));
            let mut mut_cookies = cookies.lock().unwrap();
            for hdr in self.headers().get_all(COOKIE) {
                let s = std::str::from_utf8(hdr.as_bytes())?;
                for cookie_str in s.split(';').map(|s| s.trim()) {
                    if !cookie_str.is_empty() {
                        mut_cookies.push(Cookie::parse_encoded(cookie_str)?.into_owned());
                    }
                }
            }
            self.extensions_mut().insert(cookies.clone());
        }
        Ok(self
            .extensions()
            .get::<Arc<Mutex<Vec<Cookie<'static>>>>>()
            .unwrap()
            .clone())
    }
}

/// Use cookies for session storage.
///
/// `CookieSession` creates sessions which are limited to storing
/// fewer than 4000 bytes of data (as the payload must fit into a single
/// cookie). An Internal Server Error is generated if the session contains more
/// than 4000 bytes.
///
/// A cookie may have a security policy of *signed* or *private*. Each has a
/// respective `CookieSession` constructor.
///
/// A *signed* cookie is stored on the client as plaintext alongside
/// a signature such that the cookie may be viewed but not modified by the
/// client.
///
/// A *private* cookie is stored on the client as encrypted text
/// such that it may neither be viewed nor modified by the client.
///
/// The constructors take a key as an argument.
/// This is the private key for cookie session - when this value is changed,
/// all session data is lost. The constructors will panic if the key is less
/// than 32 bytes in length.
///
/// The backend relies on `cookie` crate to create and read cookies.
/// By default all cookies are percent encoded, but certain symbols may
/// cause troubles when reading cookie, if they are not properly percent encoded.
///
/// # Examples
/// ```
/// use actix_session::CookieSession;
/// use actix_web::{web, App, HttpResponse, HttpServer};
///
/// let app = App::new().wrap(
///     CookieSession::signed(&[0; 32])
///         .domain("www.rust-lang.org")
///         .name("actix_session")
///         .path("/")
///         .secure(true))
///     .service(web::resource("/").to(|| HttpResponse::Ok()));
/// ```
#[derive(Clone)]
pub struct CookieSession(Arc<CookieSessionInner>);

impl CookieSession {
    /// Construct new *signed* `CookieSession` instance.
    ///
    /// Panics if key length is less than 32 bytes.
    pub fn signed(key: &[u8]) -> CookieSession {
        CookieSession(Arc::new(CookieSessionInner::new(
            key,
            CookieSecurity::Signed,
        )))
    }

    /// Construct new *private* `CookieSession` instance.
    ///
    /// Panics if key length is less than 32 bytes.
    pub fn private(key: &[u8]) -> CookieSession {
        CookieSession(Arc::new(CookieSessionInner::new(
            key,
            CookieSecurity::Private,
        )))
    }

    /// Sets the `path` field in the session cookie being built.
    pub fn path<S: Into<String>>(mut self, value: S) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().path = value.into();
        self
    }

    /// Sets the `name` field in the session cookie being built.
    pub fn name<S: Into<String>>(mut self, value: S) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().name = value.into();
        self
    }

    /// Sets the `domain` field in the session cookie being built.
    pub fn domain<S: Into<String>>(mut self, value: S) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().domain = Some(value.into());
        self
    }

    /// When true, prevents adding session cookies to responses until
    /// the session contains data. Default is `false`.
    ///
    /// Useful when trying to comply with laws that require consent for setting cookies.
    pub fn lazy(mut self, value: bool) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().lazy = value;
        self
    }

    /// Sets the `secure` field in the session cookie being built.
    ///
    /// If the `secure` field is set, a cookie will only be transmitted when the
    /// connection is secure - i.e. `https`
    pub fn secure(mut self, value: bool) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().secure = value;
        self
    }

    /// Sets the `http_only` field in the session cookie being built.
    pub fn http_only(mut self, value: bool) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().http_only = value;
        self
    }

    /// Sets the `same_site` field in the session cookie being built.
    pub fn same_site(mut self, value: SameSite) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().same_site = Some(value);
        self
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age(self, seconds: i64) -> CookieSession {
        self.max_age_time(Duration::seconds(seconds))
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age_time(mut self, value: time::Duration) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().max_age = Some(value);
        self
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in(self, seconds: i64) -> CookieSession {
        self.expires_in_time(Duration::seconds(seconds))
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in_time(mut self, value: Duration) -> CookieSession {
        Arc::get_mut(&mut self.0).unwrap().expires_in = Some(value);
        self
    }

    pub fn middleware<S>(self, inner_service: S) -> CookieSessionMiddleware<S> {
        CookieSessionMiddleware {
            inner_service,
            inner_session: self.0,
        }
    }
}

/// Cookie based session middleware.
#[derive(Clone)]
pub struct CookieSessionMiddleware<S> {
    inner_service: S,
    inner_session: Arc<CookieSessionInner>,
}

impl<S> Service<Request<Body>> for CookieSessionMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_service.poll_ready(cx)
    }

    /// On first request, a new session cookie is returned in response, regardless
    /// of whether any session state is set.  With subsequent requests, if the
    /// session state changes, then set-cookie is returned in response.  As
    /// a user logs out, call session.purge() to set SessionStatus accordingly
    /// and this will trigger removal of the session cookie in the response.
    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let inner = self.inner_session.clone();
        let (is_new, state) = self.inner_session.load(&mut req);
        let prolong_expiration = self.inner_session.expires_in.is_some();
        Session::set_session(&mut req, state);

        let clone = self.inner_service.clone();
        let mut service = std::mem::replace(&mut self.inner_service, clone);

        let session_state = req
            .extensions()
            .get::<Arc<Mutex<SessionInner>>>()
            .expect("Should have a session_state")
            .clone();
        Box::pin(async move {
            let mut res: Response = service.call(req).await?;
            res.extensions_mut().insert(session_state);
            let result = match Session::get_changes(&mut res) {
                (SessionStatus::Changed, state) | (SessionStatus::Renewed, state) => {
                    inner.set_cookie(&mut res, state)
                }

                (SessionStatus::Unchanged, state) if prolong_expiration => {
                    inner.set_cookie(&mut res, state)
                }

                // set a new session cookie upon first request (new client)
                (SessionStatus::Unchanged, _) => {
                    if is_new {
                        let state: HashMap<String, String> = HashMap::new();
                        inner.set_cookie(&mut res, state.into_iter())
                    } else {
                        Ok(())
                    }
                }

                (SessionStatus::Purged, _) => {
                    let _ = inner.remove_cookie(&mut res);
                    Ok(())
                }
            };

            match result {
                Ok(_) => Ok(res),
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
