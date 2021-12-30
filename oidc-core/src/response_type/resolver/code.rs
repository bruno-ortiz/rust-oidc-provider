use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::response_type::authorisation_response::AuthorisationResponse;
use crate::response_type::errors::AuthorisationError;
use crate::response_type::resolver::ResponseTypeResolver;

pub(crate) struct CodeResolver;

impl ResponseTypeResolver for CodeResolver {
    fn resolve(&self, context: &OpenIDContext) -> Result<AuthorisationResponse, AuthorisationError> {
        Ok(AuthorisationResponse::Code(AuthorisationCode("xpto".into())))
    }
}