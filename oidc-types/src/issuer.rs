use url::Url;
use serde::{Serialize, Serializer};
use std::fmt::{Display, Formatter, Debug};
use std::fmt;
use std::convert::TryInto;

pub struct Issuer(Url);

impl Issuer {
    fn new<I: TryInto<Url, Error=E>, E: Debug>(identifier: I) -> Self {
        let identifier = identifier
            .try_into()
            .expect("Configured issuer should be a valid URL");
        Issuer(identifier)
    }
}

impl Serialize for Issuer {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_newtype_struct("Issuer", &self.0)
    }
}

impl Display for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

        assert_eq!(r#""http://localhost:7000/""#, serde_json::to_string(&iss).unwrap())
    }
}
