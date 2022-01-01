use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;

use crate::response_type::errors::AuthorisationError;
use crate::response_type::resolver::ResponseTypeResolver;

pub(crate) struct CodeResolver;

impl ResponseTypeResolver for CodeResolver {
    type Output = AuthorisationCode;

    fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, AuthorisationError> {
        Ok(AuthorisationCode("xpto".into()))
    }
}
