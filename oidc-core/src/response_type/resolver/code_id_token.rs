use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::id_token::IdToken;

use crate::response_type::errors::AuthorisationError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct CodeIdTokenResolver;

impl ResponseTypeResolver for CodeIdTokenResolver {
    type Output = (AuthorisationCode, IdToken);

    fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, AuthorisationError> {
        let code = CodeResolver.resolve(context)?;
        let id_token_resolver = IDTokenResolver::new(Some(&code), None);
        let id_token = id_token_resolver.resolve(context)?;
        Ok((code, id_token))
    }
}
