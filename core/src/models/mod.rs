pub(crate) mod access_token;
pub(crate) mod authorisation_code;
pub mod client;
pub(crate) mod refresh_token;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Status {
    Awaiting,
    Consumed,
}

impl Default for Status {
    fn default() -> Self {
        Self::Awaiting
    }
}
