use crate::authorisation_code::AuthorisationCode;
use crate::id_token::IDToken;
use crate::state::State;

#[derive(Debug)]
pub enum AuthorisationResponse {
    Code(AuthorisationCode, State),
    CodeIdToken(AuthorisationCode, State, IDToken),
}
