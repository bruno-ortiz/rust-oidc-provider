pub mod access_token;
pub mod authorisation_code;
pub mod client;
pub mod grant;
pub mod refresh_token;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Status {
    Awaiting,
    Consumed,
}

impl Default for Status {
    fn default() -> Self {
        Self::Awaiting
    }
}
