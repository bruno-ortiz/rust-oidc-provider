use std::collections::HashSet;
use std::ops::Add;

use crate::configuration::claims::ClaimConfiguration::{Scoped, Standalone};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ClaimConfiguration {
    Standalone(&'static str),
    Scoped(&'static str, Vec<&'static str>),
}

impl ClaimConfiguration {
    pub fn unwrap_scoped(&self) -> Option<(&str, Vec<&str>)> {
        match self {
            Standalone(_) => None,
            Scoped(scope, claims) => Some((scope, claims.clone())),
        }
    }

    pub fn claims(&self) -> Vec<&str> {
        match self {
            Standalone(claim) => vec![claim],
            Scoped(_, claims) => claims.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClaimsSupported(HashSet<ClaimConfiguration>);

impl ClaimsSupported {
    pub fn new(claims: HashSet<ClaimConfiguration>) -> Self {
        Self(claims)
    }

    pub fn profile() -> ClaimsSupported {
        ClaimsSupported(HashSet::from([Scoped(
            "profile",
            vec![
                "name",
                "family_name",
                "given_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "updated_at",
            ],
        )]))
    }

    pub fn email() -> ClaimsSupported {
        ClaimsSupported(HashSet::from([Scoped(
            "email",
            vec!["email", "email_verified"],
        )]))
    }

    pub fn address() -> ClaimsSupported {
        ClaimsSupported(HashSet::from([Scoped("address", vec!["address"])]))
    }

    pub fn phone() -> ClaimsSupported {
        ClaimsSupported(HashSet::from([Scoped(
            "phone",
            vec!["phone_number", "phone_number_verified"],
        )]))
    }

    pub fn all() -> ClaimsSupported {
        ClaimsSupported::default()
            + ClaimsSupported::profile()
            + ClaimsSupported::address()
            + ClaimsSupported::email()
            + ClaimsSupported::phone()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClaimConfiguration> {
        self.0.iter()
    }
}

impl Add for ClaimsSupported {
    type Output = ClaimsSupported;

    fn add(self, rhs: Self) -> Self::Output {
        let mut c = self.0;
        c.extend(rhs.0);
        ClaimsSupported(c)
    }
}

impl Default for ClaimsSupported {
    fn default() -> Self {
        ClaimsSupported(HashSet::from([
            Standalone("acr"),
            Standalone("auth_time"),
            Standalone("iss"),
            Standalone("sid"),
            Scoped("openid", vec!["sub"]),
        ]))
    }
}
