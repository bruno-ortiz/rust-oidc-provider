mod response_type;
mod issuer;
mod discovery;
mod scopes;
mod pkce;
mod grant_type;
mod response_mode;
mod jws;
mod auth_method;
mod subject_type;
mod claim_type;
mod authentication_request;
mod prompt;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
