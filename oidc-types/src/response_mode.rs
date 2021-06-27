use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    FormPost,
    Fragment,
    Query,
    Jwt,
    #[serde(rename = "query.jwt")]
    QueryJwt,
    #[serde(rename = "fragment.jwt")]
    FragmentJwt,
    #[serde(rename = "form_post.jwt")]
    FormPostJwt,
}

#[cfg(test)]
mod tests {
    use crate::response_mode::ResponseMode;

    #[test]
    fn test_can_serialize_response_mode() {
        assert_eq!("form_post", serialize(&ResponseMode::FormPost));
        assert_eq!("fragment", serialize(&ResponseMode::Fragment));
        assert_eq!("query", serialize(&ResponseMode::Query));
        assert_eq!("jwt", serialize(&ResponseMode::Jwt));
        assert_eq!("query.jwt", serialize(&ResponseMode::QueryJwt));
        assert_eq!("fragment.jwt", serialize(&ResponseMode::FragmentJwt));
        assert_eq!("form_post.jwt", serialize(&ResponseMode::FormPostJwt));
    }

    #[test]
    fn test_can_deserialize_response_mode() {
        assert_eq!(ResponseMode::FormPost, deserialize("form_post"));
        assert_eq!(ResponseMode::Fragment, deserialize("fragment"));
        assert_eq!(ResponseMode::Query, deserialize("query"));
        assert_eq!(ResponseMode::Jwt, deserialize("jwt"));
        assert_eq!(ResponseMode::QueryJwt, deserialize("query.jwt"));
        assert_eq!(ResponseMode::FragmentJwt, deserialize("fragment.jwt"));
        assert_eq!(ResponseMode::FormPostJwt, deserialize("form_post.jwt"));
    }

    fn serialize(response_mode: &ResponseMode) -> String {
        serde_json::to_string(response_mode).unwrap().replace("\"", "")
    }

    fn deserialize(response_mode: &str) -> ResponseMode {
        serde_json::from_str(format!("\"{}\"", response_mode).as_str()).unwrap()
    }
}