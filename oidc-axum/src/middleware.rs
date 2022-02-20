use std::task::{Context, Poll};

use axum::http::{header, Request};
use axum::response::{IntoResponse, Response};
use futures::future::BoxFuture;
use hyper::Body;
use tower::{Layer, Service};
use tower_cookies::{Cookie, Cookies, Key};

use crate::extractors::{SessionHolder, SessionInner, SESSION_KEY};

#[derive(Clone, Debug)]
pub struct SessionManager<S> {
    inner: S,
}

impl<S> SessionManager<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Service<Request<Body>> for SessionManager<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        dbg!(req.headers().get(header::COOKIE).cloned());
        let cookies = req
            .extensions()
            .get::<Cookies>()
            .cloned()
            .expect("tower-cookies must be configured");
        let clone = self.inner.clone();
        let mut service = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            match SessionInner::load(&req).await {
                Ok(session_inner) => {
                    req.extensions_mut().insert(session_inner.clone());
                    let res: Response = service.call(req).await?;
                    let session = SessionHolder::new(session_inner.clone());
                    let mut cookie = Cookie::build(SESSION_KEY, session.session_id().to_string())
                        .http_only(true);
                    if let Some(duration) = session.duration() {
                        cookie = cookie.max_age(duration);
                    }
                    cookies.add(cookie.finish());
                    Ok(res)
                }
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}
#[derive(Clone)]
pub struct SessionManagerLayer {
    key: Option<Key>,
}

impl SessionManagerLayer {
    pub fn signed(key: &[u8]) -> Self {
        Self {
            key: Some(Key::derive_from(key)),
        }
    }
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for SessionManagerLayer {
    fn default() -> Self {
        SessionManagerLayer {
            key: Option::<Key>::None,
        }
    }
}

impl<S> Layer<S> for SessionManagerLayer {
    type Service = SessionManager<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SessionManager::new(inner)
    }
}
