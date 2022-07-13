use oidc_types::pkce::CodeChallengeMethod;

#[derive(Debug, Clone)]
pub struct PKCE {
    required: bool,
    methods: Vec<CodeChallengeMethod>,
}

impl Default for PKCE {
    fn default() -> Self {
        PKCE {
            required: false,
            methods: vec![CodeChallengeMethod::S256],
        }
    }
}
