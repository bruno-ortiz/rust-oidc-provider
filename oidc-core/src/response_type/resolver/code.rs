use crate::adapter::Adapter;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;

pub(crate) struct CodeResolver {
    adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
}

impl CodeResolver {
    pub fn new(
        adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
    ) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl ResponseTypeResolver for CodeResolver {
    type Output = AuthorisationCode;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        // let code = AuthorisationCode{
        //     code: Uuid::new_v4().to_string(),
        //     client_id: context.client.id
        // }
        todo!("implement auth code generation")
    }
}
