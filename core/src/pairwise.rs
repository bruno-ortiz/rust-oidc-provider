use quick_cache::sync::Cache;
use thiserror::Error;
use url::{Host, Url};

use oidc_types::client::ClientID;
use oidc_types::password_hasher::{HashingError, PasswordHasher};
use oidc_types::subject::Subject;

use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;

const DEFAULT_CACHE_CAPACITY: usize = 10000;

#[derive(Debug, Error, Clone)]
pub enum PairwiseError {
    #[error("Unable to determine the sector identifier for client: {}", .0)]
    SectorIdentifier(ClientID),
    #[error("Invalid host for uri: {}", .0)]
    InvalidDomain(Url),
    #[error("Host not found for uri: {}", .0)]
    HostNotFound(Url),
    #[error("Error calculating hash for pairwise sub: {}", .0)]
    Hashing(#[from] HashingError),
}

#[derive(Clone)]
pub struct PairwiseSubject(Subject);

impl PairwiseSubject {
    pub fn into_subject(self) -> Subject {
        self.0
    }
}

impl PartialEq<Subject> for PairwiseSubject {
    fn eq(&self, other: &Subject) -> bool {
        self.0 == *other
    }
}

impl PartialEq<str> for PairwiseSubject {
    fn eq(&self, other: &str) -> bool {
        self.0 == *other
    }
}

#[derive(Debug)]
pub struct PairwiseResolver {
    cache: Cache<Subject, PairwiseSubject>,
}

impl PairwiseResolver {
    pub fn calculate_pairwise_identifier(
        &self,
        subject: &Subject,
        client: &ClientInformation,
    ) -> Result<PairwiseSubject, PairwiseError> {
        self.cache.get_or_insert_with(subject, || {
            let config = OpenIDProviderConfiguration::instance();
            let hasher = config.secret_hasher();
            let sector_identifier = select_sector_identifier(client)?;
            let sub = [sector_identifier.as_bytes(), subject.as_ref()].concat();
            let hash = hasher.hash(&sub)?;
            Ok(PairwiseSubject(Subject::new(hash)))
        })
    }
}

impl Default for PairwiseResolver {
    fn default() -> Self {
        PairwiseResolver {
            cache: Cache::new(DEFAULT_CACHE_CAPACITY),
        }
    }
}

fn select_sector_identifier(client: &ClientInformation) -> Result<&str, PairwiseError> {
    let host = if let Some(sector_identifier) = &client.metadata().sector_identifier_uri {
        extract_host(sector_identifier)?
    } else {
        let redirect_uri = client
            .metadata()
            .redirect_uris
            .first()
            .ok_or_else(|| PairwiseError::SectorIdentifier(client.id()))?;
        extract_host(redirect_uri)?
    };
    Ok(host)
}

fn extract_host(uri: &Url) -> Result<&str, PairwiseError> {
    let Host::Domain(host) = uri
        .host()
        .ok_or_else(|| PairwiseError::HostNotFound(uri.clone()))?
    else {
        return Err(PairwiseError::InvalidDomain(uri.clone()));
    };
    Ok(host)
}
