use std::collections::HashMap;
use std::fmt::Formatter;

use josekit::JoseError;
use josekit::jwk::Jwk;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{EnumAccess, MapAccess, SeqAccess, Visitor};
use serde::ser::{Error, SerializeMap};
use serde_json::{Map, Value};

use crate::jose::jwt::JWT;

#[derive(PartialEq, Debug)]
pub struct JwkHolder(Jwk);

#[derive(Serialize, PartialEq, Debug)]
pub struct JwkSet {
    keys: Vec<JwkHolder>,
    #[serde(skip_serializing)]
    key_map: HashMap<String, usize>,
}

impl JwkSet {
    pub fn new(keys: Vec<JwkHolder>) -> Self {
        let mut key_map = HashMap::with_capacity(keys.len());
        for (idx, key) in keys.iter().enumerate() {
            let key_id = key.0.key_id();
            if let Some(id) = key_id {
                key_map.insert(id.to_owned(), idx);
            }
        }
        JwkSet {
            keys,
            key_map,
        }
    }
}

impl Serialize for JwkHolder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let key_map: &Map<String, Value> = self.0.as_ref();
        let mut map = serializer.serialize_map(Some(key_map.len()))?;
        for (k, v) in key_map {
            map.serialize_entry::<String, Value>(&k, &v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for JwkHolder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let map_err_fn = |err: JoseError| de::Error::custom(format!("{:?}", err));
        Map::deserialize(deserializer)
            .and_then(|map| Jwk::from_map(map).map_err(map_err_fn))
            .map(JwkHolder)
    }
}

impl<'de> Deserialize<'de> for JwkSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field { Keys }

        struct JwkSetVisitor;

        impl<'de> Visitor<'de> for JwkSetVisitor {
            type Value = JwkSet;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("an jwkSet object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error> where A: MapAccess<'de> {
                let mut keys: Option<Vec<JwkHolder>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Keys => {
                            if keys.is_some() {
                                return Err(de::Error::duplicate_field("keys"));
                            }
                            keys = Some(map.next_value()?);
                        }
                    }
                }
                let keys = keys.ok_or_else(|| de::Error::missing_field("keys"))?;
                Ok(JwkSet::new(keys))
            }
        }
        const FIELDS: &'static [&'static str] = &["keys"];
        deserializer.deserialize_struct("JwkSet", FIELDS, JwkSetVisitor)
    }
}

#[cfg(test)]
mod tests {
    use josekit::jwk::alg::ec::EcCurve;
    use josekit::jwk::Jwk;

    use crate::jose::jwk_set::{JwkHolder, JwkSet};

    #[test]
    fn test_can_serialize_jwk_set() {
        let ec_key = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let rsa_key = Jwk::generate_rsa_key(512).unwrap();
        let jwk_set = JwkSet::new(vec![JwkHolder(ec_key), JwkHolder(rsa_key)]);

        let serialized_jwk_set = serde_json::to_string(&jwk_set);

        assert!(serialized_jwk_set.is_ok());
    }

    #[test]
    fn test_can_deserialize_jwk_set() {
        let ec_key = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let rsa_key = Jwk::generate_rsa_key(512).unwrap();
        let jwk_set = JwkSet::new(vec![JwkHolder(ec_key), JwkHolder(rsa_key)]);

        let serialized_jwk_set = serde_json::to_string(&jwk_set);
        assert!(serialized_jwk_set.is_ok());

        let serialized_jwk_set = serialized_jwk_set.unwrap();

        let new_jwk_set = serde_json::from_str::<JwkSet>(&serialized_jwk_set);
        assert!(new_jwk_set.is_ok());

        assert_eq!(jwk_set, new_jwk_set.unwrap())
    }
}