#[derive(Debug)]
pub struct Routes {
    pub authorisation: &'static str,
    pub token: &'static str,
    pub jwks: &'static str,
    pub userinfo: &'static str,
    pub introspect: &'static str,
}

impl Default for Routes {
    fn default() -> Self {
        Routes {
            authorisation: "/authorise",
            token: "/token",
            jwks: "/jwks.json",
            userinfo: "/userinfo",
            introspect: "/introspect",
        }
    }
}
