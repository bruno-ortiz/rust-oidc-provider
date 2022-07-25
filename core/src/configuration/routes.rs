#[derive(Debug)]
pub struct Routes {
    pub authorisation: &'static str,
    pub jwks: &'static str,
}

impl Default for Routes {
    fn default() -> Self {
        Routes {
            authorisation: "/authorise",
            jwks: "/jwks.json",
        }
    }
}
