use std::error;
use std::fmt::{Debug, Display, Formatter};

use base64::DecodeError;
use josekit::{JoseError};

#[derive(Debug)]
pub enum JWTError {
    B64DecodeError(DecodeError),
    InvalidJwtFormat(String),
    SerDeParseError(serde_json::Error),
    JoseCreationError(JoseError),
}

impl Display for JWTError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            JWTError::B64DecodeError(err) => {
                write!(f, "Error decoding b64 jwt part, {}", err)
            }
            JWTError::InvalidJwtFormat(jwt) => {
                write!(f, "JWT has an invalid format. {}", jwt)
            }
            JWTError::SerDeParseError(err) => {
                write!(f, "Unable to parse jwt to json. {}", err)
            }
            JWTError::JoseCreationError(err) => {
                write!(f, "Error creating JWT. {:?}", err)
            }
        }
    }
}

impl error::Error for JWTError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            JWTError::B64DecodeError(ref err) => Some(err),
            JWTError::SerDeParseError(ref err) => Some(err),
            JWTError::JoseCreationError(ref err) => Some(err),
            JWTError::InvalidJwtFormat(_) => None,
        }
    }
}

impl From<DecodeError> for JWTError {
    fn from(err: DecodeError) -> Self {
        JWTError::B64DecodeError(err)
    }
}

impl From<serde_json::Error> for JWTError {
    fn from(err: serde_json::Error) -> Self {
        JWTError::SerDeParseError(err)
    }
}

impl From<JoseError> for JWTError {
    fn from(err: JoseError) -> Self {
        JWTError::JoseCreationError(err)
    }
}
