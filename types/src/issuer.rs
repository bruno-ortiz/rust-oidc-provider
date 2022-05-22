use std::convert::TryInto;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

use serde::{Serialize, Serializer};
use url::Url;

#[derive(Debug)]
pub struct Issuer(Url);

impl Issuer {
    pub fn new<I: TryInto<Url, Error = E>, E: Debug>(identifier: I) -> Self {
        match identifier.try_into() {
            Ok(i) => Issuer(i),
            Err(error) => panic!("Configured issuer should be a valid URL. Err: {:?}", error),
        }
    }

    pub fn inner_ref(&self) -> &Url {
        &self.0
    }
}

impl Serialize for Issuer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("Issuer", &self.0)
    }
}

impl Display for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Issuer> for String {
    fn from(iss: Issuer) -> Self {
        iss.0.into()
    }
}

impl From<&Issuer> for String {
    fn from(iss: &Issuer) -> Self {
        iss.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::Issuer;

    #[test]
    fn test_can_create_issuer() {
        let iss = Issuer::new("http://localhost:7000");

        assert_eq!("http://localhost:7000/", iss.to_string())
    }

    #[test]
    #[should_panic]
    fn test_invalid_issuer() {
        Issuer::new("this is invalid");
    }

    #[test]
    fn test_can_serialize_issuer() {
        let iss = Issuer::new("http://localhost:7000");

        assert_eq!(
            r#""http://localhost:7000/""#,
            serde_json::to_string(&iss).unwrap()
        )
    }
}
