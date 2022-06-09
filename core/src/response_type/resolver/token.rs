use crate::access_token::AccessToken;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;
use async_trait::async_trait;
use time::Duration;
use uuid::Uuid;

pub struct TokenResolver;

#[async_trait]
impl ResponseTypeResolver for TokenResolver {
    type Output = AccessToken;

    async fn resolve(&self, _context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        Ok(AccessToken::new(
            Uuid::new_v4().to_string(),
            "Bearer".to_owned(),
            Duration::minutes(10),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_can_create_access_token() {
        todo!()
    }
}
