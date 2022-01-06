use url::Url;

use crate::context::OpenIDContext;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::encoder::ResponseModeEncoder;
use crate::response_type::resolver::ResponseTypeResolver;

struct AuthorisationService<T: ResponseTypeResolver> {
    resolver: T,
}

impl<T> AuthorisationService<T>
where
    T: ResponseTypeResolver,
{
    fn authorise(self, sub: &str, context: &OpenIDContext) -> anyhow::Result<Url> {
        let authorisation_response = self.resolver.resolve(context)?;
        let encoder = QueryEncoder;
        encoder.encode(context, authorisation_response);
        todo!()
    }
}
