use oidc_types::pkce::CodeChallengeMethod;

#[derive(Debug)]
pub struct PKCE {
    required: bool,
    methods: Vec<CodeChallengeMethod>,
}

impl Default for PKCE {
    fn default() -> Self {
        PKCE {
            required: true,
            methods: vec![CodeChallengeMethod::S256],
        }
    }
}
