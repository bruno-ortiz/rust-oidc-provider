use derive_more::From;
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::code::Code;
use crate::grant_type::GrantType;
use crate::scopes::Scopes;

#[derive(Debug, Clone, Deserialize, From)]
#[serde(tag = "grant_type")]
pub enum TokenRequestBody {
    #[serde(rename = "authorization_code")]
    AuthorisationCodeGrant(AuthorisationCodeGrant),
    #[serde(rename = "refresh_token")]
    RefreshTokenGrant(RefreshTokenGrant),
    #[serde(rename = "client_credentials")]
    ClientCredentialsGrant(ClientCredentialsGrant),
}

impl TokenRequestBody {
    pub fn grant_type(&self) -> GrantType {
        match self {
            TokenRequestBody::AuthorisationCodeGrant(_) => GrantType::AuthorizationCode,
            TokenRequestBody::RefreshTokenGrant(_) => GrantType::RefreshToken,
            TokenRequestBody::ClientCredentialsGrant(_) => GrantType::ClientCredentials,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorisationCodeGrant {
    pub code: Code,
    pub redirect_uri: Url,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshTokenGrant {
    pub refresh_token: Uuid,
    pub scope: Option<Scopes>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientCredentialsGrant {
    pub scope: Option<Scopes>,
}

#[cfg(test)]
mod tests {
    use crate::token_request::TokenRequestBody;

    #[test]
    fn test_can_deserialize_into_refresh_token() {
        let json = r#"
        {
          "grant_type": "refresh_token",
          "refresh_token":"bf1f8ef6-9aca-49e3-8e28-03767b776ddf",
          "scope": "openid"
        }
        "#;

        let req: TokenRequestBody = serde_json::from_str(json).unwrap();

        assert!(matches!(req, TokenRequestBody::RefreshTokenGrant(_)))
    }

    #[test]
    fn test_can_deserialize_into_authorization_code() {
        let json = r#"
        {
          "grant_type": "authorization_code",
          "code":"1234",
          "redirect_uri": "https://google.com"
        }
        "#;

        let req: TokenRequestBody = serde_json::from_str(json).unwrap();

        assert!(matches!(req, TokenRequestBody::AuthorisationCodeGrant(_)))
    }

    #[test]
    fn test_can_deserialize_into_client_credentials() {
        let json = r#"
        {
          "grant_type": "client_credentials",
          "scope": "openid"
        }
        "#;

        let req: TokenRequestBody = serde_json::from_str(json).unwrap();

        assert!(matches!(req, TokenRequestBody::ClientCredentialsGrant(_)))
    }
}
