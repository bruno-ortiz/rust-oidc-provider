use std::process::id;

use crate::access_token::AccessToken;
use crate::authorisation_code::AuthorisationCode;
use crate::id_token::IdToken;
use crate::state::State;

#[derive(Debug)]
pub enum AuthorisationResponse {
    Code(AuthorisationCode),
    IdToken(IdToken),
    Token(AccessToken),
    CodeIdToken(AuthorisationCode, IdToken),
    CodeToken(AuthorisationCode, AccessToken),
    IdTokenToken(IdToken, AccessToken),
    CodeIdTokenToken(AuthorisationCode, IdToken, AccessToken),
}

impl AuthorisationResponse {
    pub fn get_code_or_panic(self) -> AuthorisationCode {
        match self {
            AuthorisationResponse::Code(code) => code,
            AuthorisationResponse::CodeIdToken(code, _) => code,
            AuthorisationResponse::CodeToken(code, _) => code,
            AuthorisationResponse::CodeIdTokenToken(code, _, _) => code,
            AuthorisationResponse::IdToken(_) => panic!("IdToken response does not have an AuthorizationCode"),
            AuthorisationResponse::Token(_) => panic!("Token response does not have an AuthorizationCode"),
            AuthorisationResponse::IdTokenToken(_, _) => panic!("IdTokenToken response does not have an AuthorizationCode"),
        }
    }

    pub fn get_id_token_or_panic(self) -> IdToken {
        match self {
            AuthorisationResponse::IdToken(id_token) => id_token,
            AuthorisationResponse::CodeIdToken(_, id_token) => id_token,
            AuthorisationResponse::CodeIdTokenToken(_, id_token, _) => id_token,
            AuthorisationResponse::IdTokenToken(id_token, _) => id_token,
            AuthorisationResponse::Code(_) => panic!("Code response does not have an IdToken"),
            AuthorisationResponse::CodeToken(_, _) => panic!("CodeToken response does not have an IdToken"),
            AuthorisationResponse::Token(_) => panic!("Token response does not have an IdToken"),
        }
    }
}