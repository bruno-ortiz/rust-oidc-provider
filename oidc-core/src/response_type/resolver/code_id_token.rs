use chrono::Utc;

use crate::access_token::AccessToken;
use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::hash::TokenHasher;
use crate::id_token::IdToken;
use crate::response_type::authorisation_response::AuthorisationResponse;
use crate::response_type::errors::AuthorisationError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct CodeIdTokenResolver;

impl ResponseTypeResolver for CodeIdTokenResolver {
    fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let code_response = CodeResolver.resolve(context)?;
        let code = code_response.get_code_or_panic();
        let id_token_resolver = IDTokenResolver::new(Some(&code), None);
        let id_token_response = id_token_resolver.resolve(context)?;
        let id_token = id_token_response.get_id_token_or_panic();
        Ok(AuthorisationResponse::CodeIdToken(code, id_token))
    }
}
