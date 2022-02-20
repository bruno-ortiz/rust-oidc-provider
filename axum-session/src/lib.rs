use std::collections::HashMap;
use std::convert::Infallible;
use std::mem;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use axum::extract::{FromRequest, RequestParts};
use axum::http::{Extensions, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use hyper::Body;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Error as SerDeError;
use thiserror::Error;

pub mod cookie;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    SerDeError(#[from] SerDeError),
    #[error("Internal error: {}", .0)]
    InternalError(String),
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let mut res = self.to_string().into_response();
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        res
    }
}

/// Status of a [`Session`].
#[derive(PartialEq, Clone, Debug)]
pub enum SessionStatus {
    /// Session has been updated and requires a new persist operation.
    Changed,

    /// Session is flagged for deletion and should be removed from client and server.
    ///
    /// Most operations on the session after purge flag is set should have no effect.
    Purged,

    /// Session is flagged for refresh.
    ///
    /// For example, when using a backend that has a TTL (time-to-live) expiry on the session entry,
    /// the session will be refreshed even if no data inside it has changed. The client may also
    /// be notified of the refresh.
    Renewed,

    /// Session is unchanged from when last seen (if exists).
    ///
    /// This state also captures new (previously unissued) sessions such as a user's first
    /// site visit.
    Unchanged,
}

impl Default for SessionStatus {
    fn default() -> SessionStatus {
        SessionStatus::Unchanged
    }
}

#[derive(Default)]
pub struct SessionInner {
    state: HashMap<String, String>,
    status: SessionStatus,
}

#[derive(Clone)]
pub struct Session(Arc<Mutex<SessionInner>>);

impl Session {
    pub fn insert(
        &self,
        key: impl Into<String>,
        value: impl Serialize,
    ) -> Result<(), SessionError> {
        let mut inner = self.0.lock().unwrap();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            let val = serde_json::to_string(&value);
            match val {
                Ok(val) => {
                    inner.state.insert(key.into(), val);
                }
                Err(err) => return Err(SessionError::SerDeError(err)),
            }
        }

        Ok(())
    }

    /// Get a `value` from the session.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, SessionError> {
        let guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(err) => return Err(SessionError::InternalError(err.to_string())),
        };
        if let Some(s) = guard.state.get(key) {
            let res = serde_json::from_str(s);
            match res {
                Ok(parsed) => Ok(Some(parsed)),
                Err(err) => Err(SessionError::SerDeError(err)),
            }
        } else {
            Ok(None)
        }
    }

    pub fn remove(&self, key: &str) -> Option<String> {
        let mut inner = self.0.lock().unwrap();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            return inner.state.remove(key);
        }

        None
    }

    pub fn remove_as<T: DeserializeOwned>(&self, key: &str) -> Option<Result<T, String>> {
        self.remove(key)
            .map(|val_str| match serde_json::from_str(&val_str) {
                Ok(val) => Ok(val),
                Err(_err) => {
                    log::debug!(
                        "removed value (key: {}) could not be deserialized as {}",
                        key,
                        std::any::type_name::<T>()
                    );
                    Err(val_str)
                }
            })
    }

    pub fn clear(&self) {
        let mut inner = self.0.lock().unwrap();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.clear()
        }
    }

    pub fn purge(&self) {
        let mut inner = self.0.lock().unwrap();
        inner.status = SessionStatus::Purged;
        inner.state.clear();
    }

    pub fn renew(&self) {
        let mut inner = self.0.lock().unwrap();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Renewed;
        }
    }

    pub fn set_session(req: &mut Request<Body>, data: impl IntoIterator<Item = (String, String)>) {
        let session = Session::get_session(&mut *req.extensions_mut()); //todo: what to do about this unwrap?
        let mut inner = session.0.lock().unwrap();
        inner.state.extend(data);
    }

    /// Returns session status and iterator of key-value pairs of changes.
    pub fn get_changes<B>(
        res: &mut Response<B>,
    ) -> (SessionStatus, impl Iterator<Item = (String, String)>) {
        if let Some(s_impl) = res.extensions().get::<Arc<Mutex<SessionInner>>>() {
            let state = mem::take(&mut s_impl.lock().unwrap().state);
            (s_impl.lock().unwrap().status.clone(), state.into_iter())
        } else {
            (SessionStatus::Unchanged, HashMap::new().into_iter())
        }
    }

    fn get_session(extensions: &mut Extensions) -> Session {
        if let Some(s_impl) = extensions.get::<Arc<Mutex<SessionInner>>>() {
            return Session(Arc::clone(s_impl));
        }
        let inner = Arc::new(Mutex::new(SessionInner::default()));
        extensions.insert(inner.clone());
        Session(inner)
    }
}

#[async_trait]
impl<B> FromRequest<B> for Session
where
    B: Send,
{
    type Rejection = Infallible;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        Ok(Session::get_session(req.extensions_mut().unwrap()))
    }
}

#[cfg(test)]
mod tests {}
