use crate::scopes::Scopes;

#[derive(Debug)]
pub struct Grant {
    scopes: Scopes,
}

impl Grant {
    pub fn new(scopes: Scopes) -> Self {
        Self { scopes }
    }
}
