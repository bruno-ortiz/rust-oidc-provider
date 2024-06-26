use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use futures::future::BoxFuture;
use futures::FutureExt;
use tower::{Layer, Service};
use tower_cookies::{Cookie, Cookies, Key};

use crate::extractors::{SessionHolder, SessionInner, SESSION_KEY};

#[derive(Clone)]
pub struct SessionManager<S> {
    inner: S,
    key: Arc<Option<Key>>,
}

impl<S> SessionManager<S> {
    pub fn new(inner: S, key: Arc<Option<Key>>) -> Self {
        Self { inner, key }
    }
}

impl<S> Service<Request> for SessionManager<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let cookies = req
            .extensions()
            .get::<Cookies>()
            .cloned()
            .expect("tower-cookies must be configured");

        let clone = self.inner.clone();
        let mut service = std::mem::replace(&mut self.inner, clone);

        let cloned_key = self.key.clone();
        async move {
            match SessionInner::load(req, cloned_key.as_ref().as_ref()).await {
                Ok((mut req, session_inner)) => {
                    req.extensions_mut().insert(session_inner.clone());
                    let res: Response = service.call(req).await?;
                    let session = SessionHolder::new(session_inner.clone());
                    let mut cookie = Cookie::build((SESSION_KEY, session.session_id().to_string()))
                        .http_only(true);
                    if let Some(duration) = session.duration() {
                        cookie = cookie.max_age(duration);
                    }
                    if let Some(key) = &*cloned_key {
                        cookies.signed(key).add(cookie.build());
                    } else {
                        cookies.add(cookie.build());
                    }
                    Ok(res)
                }
                Err(err_response) => Ok(err_response),
            }
        }
        .boxed()
    }
}
#[derive(Clone, Default)]
pub struct SessionManagerLayer {
    key: Arc<Option<Key>>,
}

impl SessionManagerLayer {
    pub fn signed(key: &[u8]) -> Self {
        Self {
            key: Arc::new(Some(Key::derive_from(key))),
        }
    }
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for SessionManagerLayer {
    type Service = SessionManager<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SessionManager::new(inner, self.key.clone())
    }
}
