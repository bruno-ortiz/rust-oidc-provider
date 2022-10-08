use axum::async_trait;
use serde_json::json;
use time::OffsetDateTime;

use oidc_core::profile::{ProfileData, ProfileError, ProfileResolver};
use oidc_types::subject::Subject;

#[derive(Debug)]
pub struct MockProfileResolver;

#[async_trait]
impl ProfileResolver for MockProfileResolver {
    async fn resolve(&self, sub: &Subject) -> Result<ProfileData, ProfileError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        Ok(ProfileData::try_from(json!({
            "sub" : sub.to_string(),
            "name": "Xose Vinicius Almanara",
            "nickname": "xovial",
            "given_name":"Xose",
            "family_name": "Almanara",
            "middle_name":"Vinicius",
            "preferred_username":"xovial",
            "profile":"https://test.com",
            "picture":"https://test.com",
            "website":"https://test.com",
            "gender":"M",
            "birthdate":"1991-04-06",
            "zoneinfo":"Interiorzao",
            "locale":"Voti",
            "updated_at": now,
            "email": "xovial1991@email.com",
            "email_verified": true,
            "phone_number":"+55 (11) 90000-0000",
            "phone_number_verified":true,
            "address": {
                "formatted": "Al. Ribeiro da Silva 811, Sao Paulo,Brazil",
                "street_address": "Al. Ribeiro da Silva 811",
                "locality": "Sao Paulo",
                "postal_code": "00000-000",
                "country": "Brazil",
            }

        }))?)
    }
}
