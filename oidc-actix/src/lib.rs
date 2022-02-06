mod configure;
mod routes;
mod extractors;

pub use configure::oidc_configuration;

#[cfg(test)]
mod tests {}
