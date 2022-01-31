mod configure;
mod routes;
mod session;

pub use configure::oidc_configuration;

#[cfg(test)]
mod tests {}
