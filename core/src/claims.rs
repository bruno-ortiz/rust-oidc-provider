use std::collections::HashMap;

use serde_json::Value;

use oidc_types::claims::{ClaimOptions, Claims};
use oidc_types::scopes::Scopes;

use crate::error::OpenIdError;
use crate::profile::ProfileData;

pub(crate) fn get_id_token_claims<'a>(
    profile: &'a ProfileData,
    requested_claims: Option<&'a Claims>,
) -> Result<HashMap<&'a str, &'a Value>, OpenIdError> {
    //TODO: make possible to filter rejected claims
    let mut claims = HashMap::new();
    if let Some(requested_claims) = requested_claims {
        let id_token_claims = &requested_claims.id_token;
        let filtered = filter_claims(profile, id_token_claims)?;
        claims.extend(filtered);
    };

    Ok(claims)
}

pub(crate) fn get_userinfo_claims<'a>(
    profile: &'a ProfileData,
    requested_claims: Option<&'a Claims>,
    scopes: Option<&Scopes>,
) -> Result<HashMap<&'a str, &'a Value>, OpenIdError> {
    //TODO: make possible to filter rejected claims
    let mut claims = scopes.map(|it| profile.claims(it)).unwrap_or_default();
    if let Some(requested_claims) = requested_claims {
        let userinfo_claims = &requested_claims.userinfo;
        let filtered = filter_claims(profile, userinfo_claims)?;
        claims.extend(filtered);
    };
    Ok(claims)
}

fn filter_claims<'a, 'b>(
    profile: &'a ProfileData,
    requested_claims: &'b HashMap<String, Option<ClaimOptions>>,
) -> Result<HashMap<&'b str, &'a Value>, OpenIdError> {
    let mut claims = HashMap::new();
    if !requested_claims.is_empty() {
        for (claim, options) in requested_claims {
            if let Some(claim_value) = profile.claim(claim.as_str()) {
                match options {
                    Some(options) if !options.validate(claim_value) => {
                        return Err(OpenIdError::invalid_grant(
                            "Requested claims did not match their requirements",
                        ))
                    }
                    _ => {
                        claims.insert(claim.as_str(), claim_value);
                    }
                }
            }
        }
    }
    Ok(claims)
}
