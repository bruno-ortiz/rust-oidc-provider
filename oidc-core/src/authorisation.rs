use url::Url;

use crate::configuration::OpenIDProviderConfiguration;
use crate::response_type::resolver::{DynamicResponseTypeResolver, ResponseTypeResolver};

struct AuthorisationService;

impl AuthorisationService {
    fn authorise() -> anyhow::Result<Url> {
        //authorize?response_type="code id_token"
        //callback?code="xpto"&id_token="abc"
        todo!()
    }
}
