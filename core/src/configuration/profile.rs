#[derive(Debug, Clone)]
pub enum ClaimConfiguration {
    Standalone(&'static str),
    Scoped(&'static str, Vec<&'static str>),
}

impl ClaimConfiguration {
    pub fn unwrap_scoped(&self) -> Option<(&str, Vec<&str>)> {
        match self {
            ClaimConfiguration::Standalone(_) => None,
            ClaimConfiguration::Scoped(scope, claims) => Some((scope, claims.clone())),
        }
    }

    pub fn claims(&self) -> Vec<&str> {
        match self {
            ClaimConfiguration::Standalone(claim) => vec![claim],
            ClaimConfiguration::Scoped(_, claims) => claims.clone(),
        }
    }
}
