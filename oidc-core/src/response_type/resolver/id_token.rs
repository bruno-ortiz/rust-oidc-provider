use std::rc::Rc;

use chrono::Utc;

use crate::access_token::AccessToken;
use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::hash::TokenHasher;
use crate::id_token::IdToken;
use crate::response_type::authorisation_response::AuthorisationResponse;
use crate::response_type::errors::AuthorisationError;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct IDTokenResolver<'a> {
    code: Option<&'a AuthorisationCode>,
    token: Option<&'a AccessToken>,
}

impl<'a> IDTokenResolver<'a> {
    pub fn new(code: Option<&'a AuthorisationCode>, token: Option<&'a AccessToken>) -> Self {
        IDTokenResolver { code, token }
    }
}

impl ResponseTypeResolver for IDTokenResolver<'_> {
    fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let state = context
            .request
            .state
            .as_ref()
            .ok_or(AuthorisationError::MissingState)?;
        let signing_key = context
            .configuration
            .signing_key()
            .ok_or(AuthorisationError::SigningKeyNotConfigured)?;
        let s_hash = state
            .hash(signing_key)
            .map_err(|source| AuthorisationError::HashingErr {
                prop: "state".to_owned(),
                source,
            })?;
        let id_token = IdToken::builder::<Utc>()
            .with_s_hash(s_hash)
            .build(signing_key)
            .map_err(|err| AuthorisationError::IdTokenCreationError { source: err })?;
        Ok(AuthorisationResponse::IdToken(id_token))
    }
}
