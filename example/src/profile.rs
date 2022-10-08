use axum::async_trait;
use serde_json::json;

use oidc_core::profile::{ProfileData, ProfileError, ProfileResolver};
use oidc_types::subject::Subject;

#[derive(Debug)]
pub struct MockProfileResolver;

#[async_trait]
impl ProfileResolver for MockProfileResolver {
    async fn resolve(&self, sub: &Subject) -> Result<ProfileData, ProfileError> {
        Ok(ProfileData::try_from(json!({
            "sub" : sub.to_string(),
            "name": "Xose",
            "nickname": "xovial"
        }))?)
    }
}
