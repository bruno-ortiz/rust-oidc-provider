use getset::{CopyGetters, Getters};
use oidc_types::pkce::CodeChallengeMethod;

#[derive(Debug, Clone, Getters, CopyGetters)]
pub struct PKCE {
    #[get_copy = "pub"]
    required: bool,
    #[get = "pub"]
    methods_supported: Vec<CodeChallengeMethod>,
}

impl Default for PKCE {
    fn default() -> Self {
        PKCE {
            required: false,
            methods_supported: vec![CodeChallengeMethod::S256],
        }
    }
}
