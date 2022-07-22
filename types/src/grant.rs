use crate::scopes::Scopes;

//we are enveloping scopes in a grant type so in the future
// we may be able to ensure other types of checks in a grant,
// like max duration for example
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Grant {
    scopes: Scopes,
}

impl Grant {
    pub fn new(scopes: Scopes) -> Self {
        Self { scopes }
    }

    pub fn scopes(&self) -> &Scopes {
        &self.scopes
    }
}
