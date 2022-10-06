use std::collections::HashMap;
use std::fmt::{Debug, Display};

use anyhow::anyhow;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::configuration::OpenIDProviderConfiguration;
use crate::models::grant::Grant;
use crate::profile::ProfileError::FormatMismatch;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("Profile not found")]
    NotFound,
    #[error("Unexpected format")]
    FormatMismatch(#[source] anyhow::Error),
    #[error("Error fetching profile information")]
    FetchError(#[from] anyhow::Error),
}

#[async_trait]
pub trait ProfileResolver {
    async fn resolve(&self, sub: &Subject) -> Result<ProfileData, ProfileError>;
}

#[derive(Debug, Deserialize)]
pub struct ProfileData(HashMap<String, Value>);

impl ProfileData {
    fn empty() -> Self {
        Self(HashMap::new())
    }

    pub async fn get(grant: &Grant) -> Result<ProfileData, ProfileError> {
        let configuration = OpenIDProviderConfiguration::instance();
        Ok(configuration
            .profile_resolver()
            .resolve(grant.subject())
            .await?
            .append("auth_time", grant.auth_time())
            .append("acr", grant.acr())
            .append("sub", grant.subject()) //todo: resolve pairwise here?
            .maybe_append("amr", grant.amr().as_ref()))
    }

    pub fn claim(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn claims(&self, scope: &Scopes) -> HashMap<&str, &Value> {
        let config = OpenIDProviderConfiguration::instance();
        let claims_supported = config
            .claims_supported()
            .iter()
            .filter_map(|it| it.unwrap_scoped())
            .collect::<HashMap<_, _>>();
        scope
            .iter()
            .flat_map(|it| claims_supported.get(it.value_ref()))
            .flatten()
            .filter_map(|&it| self.claim(it).map(|c| (it, c)))
            .collect()
    }

    pub fn maybe_append<T: Display>(self, key: &str, value: Option<T>) -> Self {
        match value {
            None => self,
            Some(value) => self.append(key, value),
        }
    }

    pub fn append<T: Display>(mut self, key: &str, value: T) -> Self {
        self.0.insert(key.to_owned(), value.to_string().into());
        self
    }
}

impl TryFrom<Value> for ProfileData {
    type Error = ProfileError;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        match v {
            Value::Object(data) => Ok(ProfileData(data.into_iter().collect())),
            _ => Err(FormatMismatch(anyhow!(
                "Expected json object found {:?}",
                v
            ))),
        }
    }
}

pub struct NoOpProfileResolver;

#[async_trait]
impl ProfileResolver for NoOpProfileResolver {
    async fn resolve(&self, _sub: &Subject) -> Result<ProfileData, ProfileError> {
        Ok(ProfileData::empty())
    }
}
