#[derive(Debug)]
pub enum Mode {
    Lax,
    Strict,
}

#[derive(Debug)]
pub struct RequestObjectConfiguration {
    pub mode: Mode,
    pub request: bool,
    pub request_uri: bool,
    pub require_signed_request_object: bool,
    pub require_uri_registration: bool,
}

impl Default for RequestObjectConfiguration {
    fn default() -> Self {
        Self {
            mode: Mode::Lax,
            request: false,
            request_uri: true,
            require_signed_request_object: false,
            require_uri_registration: true,
        }
    }
}
