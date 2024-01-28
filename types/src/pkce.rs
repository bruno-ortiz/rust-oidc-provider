use base64::Engine;
use std::fmt::{Display, Formatter};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as base64_engine;
use encoding::all::ASCII;
use encoding::{EncoderTrap, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::token_request::AuthorisationCodeGrant;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub enum CodeChallengeMethod {
    #[serde(rename = "lowercase")]
    Plain,
    S256,
}

impl Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeChallengeMethod::Plain => write!(f, "plain"),
            CodeChallengeMethod::S256 => write!(f, "S256"),
        }
    }
}
#[derive(Debug, Error)]
pub enum CodeChallengeError {
    #[error("{}", .0)]
    Ascii(String),
    #[error("Code challenge mismatch, invalid verifier")]
    Mismatch,
    #[error("Missing PKCE verifier in request")]
    MissingVerifier,
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize, PartialEq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    pub fn new<S: Into<String>>(cc: S) -> Self {
        Self(cc.into())
    }
    pub fn calculate(
        verifier: &str,
        method: CodeChallengeMethod,
    ) -> Result<Self, CodeChallengeError> {
        let code_challenge = match method {
            CodeChallengeMethod::Plain => Self(verifier.to_owned()),
            CodeChallengeMethod::S256 => {
                let ascii_encoded = ASCII
                    .encode(verifier, EncoderTrap::Strict)
                    .map_err(|err| CodeChallengeError::Ascii(err.into_owned()))?;
                let hash = &Sha256::digest(ascii_encoded)[..];
                let b64_encoded = base64_engine.encode(hash);
                Self(b64_encoded)
            }
        };
        Ok(code_challenge)
    }
}

pub fn validate_pkce(
    grant: &AuthorisationCodeGrant,
    code_challenge: Option<&CodeChallenge>,
    code_challenge_method: Option<CodeChallengeMethod>,
) -> Result<(), CodeChallengeError> {
    if let (Some(challenge), Some(method)) = (code_challenge, code_challenge_method) {
        if let Some(ref verifier) = grant.code_verifier {
            let cc = CodeChallenge::calculate(verifier, method)?;
            if cc != *challenge {
                return Err(CodeChallengeError::Mismatch);
            }
        } else {
            return Err(CodeChallengeError::MissingVerifier);
        }
    }
    Ok(())
}

impl Display for CodeChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::pkce::{CodeChallenge, CodeChallengeError, CodeChallengeMethod};

    #[test]
    fn test_can_calculate_challenge() {
        let verifier = "some-shallow-verifier-32-length!";
        let challenge = CodeChallenge::calculate(verifier, CodeChallengeMethod::S256)
            .expect("expected valid code challenge");

        assert_eq!(
            CodeChallenge::new("9BKJ8IE_1FLFbp-AH4u4EsbmM7IIEC1L6pvxcBApgBE"),
            challenge
        )
    }

    #[test]
    fn test_cannot_calculate_challenge_invalid_verifier() {
        let verifier = "non ascii verifier 日本人 中國的";
        if let CodeChallengeError::Ascii(err) =
            CodeChallenge::calculate(verifier, CodeChallengeMethod::S256)
                .expect_err("expected error")
        {
            assert_eq!("unrepresentable character".to_owned(), err);
        } else {
            panic!("Invalid error")
        }
    }
}
