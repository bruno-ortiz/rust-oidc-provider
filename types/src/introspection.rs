use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectionRequestBody {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Default)]
#[builder(setter(into, strip_option), default, pattern = "owned")]
pub struct IntrospectionResponse {
    active: bool,
    sub: Option<String>,
    client_id: Option<String>,
    token_type: Option<String>,
    exp: Option<u64>,
    iat: Option<u64>,
    nbf: Option<u64>,
    scope: Option<String>,
    aud: Option<String>,
    iss: Option<String>,
    jti: Option<String>,
}

impl IntrospectionResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            client_id: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            scope: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
}
