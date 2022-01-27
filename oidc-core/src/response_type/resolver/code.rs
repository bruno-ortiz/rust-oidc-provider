use async_trait::async_trait;

use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;

pub(crate) struct CodeResolver;

#[async_trait]
impl ResponseTypeResolver for CodeResolver {
    type Output = AuthorisationCode;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        todo!("implement auth code generation")
    }
}
