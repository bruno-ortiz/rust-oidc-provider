mod configure;
mod routes;
mod extractor;

pub use configure::oidc_configuration;

#[cfg(test)]
mod tests {}
