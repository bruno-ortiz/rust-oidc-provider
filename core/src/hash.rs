use josekit::jwk::Jwk;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

use oidc_types::hash::Hashable;

#[derive(Debug, Error)]
pub enum HashingError {
    #[error("Invalid JWK used to hash a token")]
    InvalidKey,
    #[error("Invalid hashing algorithm in JWK. {:?}", .0)]
    InvalidHashAlgorithm(String),
}

pub trait TokenHasher {
    fn hash(&self, key: &Jwk) -> Result<String, HashingError>;
}

impl<T> TokenHasher for T
where
    T: Hashable,
{
    fn hash(&self, key: &Jwk) -> Result<String, HashingError> {
        let id = self.identifier();
        let algorithm = key
            .algorithm()
            .ok_or(HashingError::InvalidKey)?
            .to_uppercase();
        let hash = match &algorithm[..] {
            "ES256" | "RS256" | "HS256" | "PS256" => Sha256::digest(id.as_bytes()).to_vec(),
            "ES384" | "RS384" | "HS384" | "PS384" => Sha384::digest(id.as_bytes()).to_vec(),
            "ES512" | "RS512" | "HS512" | "PS512" => Sha512::digest(id.as_bytes()).to_vec(),
            _ => {
                return Err(HashingError::InvalidHashAlgorithm(algorithm));
            }
        };
        let first_half = &hash[..hash.len() / 2];
        Ok(base64::encode(first_half))
    }
}

#[cfg(test)]
mod tests {
    use josekit::jwk::Jwk;
    use oidc_types::client::ClientID;
    use time::{Duration, OffsetDateTime};
    use url::Url;

    use oidc_types::scopes;
    use oidc_types::subject::Subject;

    use crate::hash::TokenHasher;
    use crate::models::authorisation_code::{AuthorisationCode, CodeStatus};

    #[test]
    fn test_can_hash() {
        let code = AuthorisationCode {
            code: String::from("some-value"),
            client_id: ClientID::default(),
            subject: Subject::new("sub"),
            scope: scopes!("openid accounts"),
            redirect_uri: Url::parse("https://test.com/callback").unwrap(),
            code_challenge: None,
            code_challenge_method: None,
            status: CodeStatus::Awaiting,
            expires_in: OffsetDateTime::now_utc() + Duration::minutes(10),
        };
        let rsa_key = Jwk::from_bytes(r#"
        {
            "p": "2Z1co6mhAXOtwSb1szKBcHd1jCyddlXr401qp3v_VnRMCoYKxgVSwSbuxOZjhtfKBb_Mc6kE6Je6rqWK_rv6cP0ks1HgPj0tsoY_9CBfxFVqYJNKPg4pN56E2bJNgNi-QbwPjCryHIdFeg_Z6_aH9faEekrCKEUqz8BkOeQgVOU",
            "kty": "RSA",
            "q": "p9JlJzQ95xZ8EV85RpGrd-jNMTj8W481LEEFhzG9LVHftxLLUcRykdxRpWDBGBPzNufLJBta69AGaPh2SUS8wZ2NqXcMSSzS5i6jbG4rMHhm5p7sUCb4WVzgtYNRCWja3IZDOj4okSlwV7fwVNoE0Ss5NLtGxdgowJFtlKoLYD0",
            "d": "cT9-1AtogU18LXHPhlj9XIgi1NaPP6Tzb6QTvEXbdGfmKnf93zdEP_9luEtzQ4iShla7AIeJw_unTw7XYTnHuOmKICRntWuf3Lv11OcHIC6b-bkV7Hn2JwMmLjOtSkVhWWveUh8kcbCcZjACtLCtCkNfVxxyOEuta0rmGKRB7Gv0khxLIVhEafX_Zd6i5FJvB3xy9JCxRQbXwPX6aRva-Rmr3cm6ruwzmpU7aAK9kHU28Q-LNt0s7cehH0QCi4fmMNBIN3_OxPo9madikL9mcH_cBPlrP--jKk6sIjeR-q8Pf4QzgbHn-RvlP2EWSwmgF6R73P2O551iK4De-ifLYQ",
            "e": "AQAB",
            "use": "sig",
            "kid": "r-4-wCX8jS7L5pbXQ-6APrf2O5Go1DOEsJXS8AghDiw",
            "qi": "qmpQ-cleaW7vr7B8XhvPIY3Xn2g2OzsufM0T8HetT60OUIVZddcdxJZffUvTt_U8uajGmiXtStusRJBtOblZuB74NBV8zx5vapow7Ncs3ZK7ThIAM2C8aDjtxiaaALmD6ktqM72OYEDDBJlFO3khvfvmCl0BeK3xhbXR0hCwXBg",
            "dp": "I-JuH1LeiPXBZkN9arJeY-RfDuFgid37Sv0-JCYvYdtFmsqlxiekkNNRtkhjix3UY4RQO5ZYh95VW21S8VSgJLepsKREvR6rhW_b5e7cu-x14T0IlhkRtOk_8QIVA7U6Em7nhW6jhA7OZyVsAxwhKW8gQ2ZGhAt71sxb-qvipP0",
            "alg": "RS256",
            "dq": "jHp-t-lwI99bbYNDQ4IugUo7cQedntrqjKfFA90r2SLe3LV7wm9p5BUDtyadnBUfEwfGsOvBGQHiS74n7b7_Lic_bOq9OwetZocFv38c4g73O_cuIw3r94nag7ZvgCvogI5W-gsMFC8W3iaXo794JstCsJRPcs81lbRmgPoyWZU",
            "n": "jqiAgSrXcqFxYCYXIK9tqxjipf00nLuCpTFKqsrnu5mp8LKZskyZ_fOHntpk_Fkc1twnrRwluptKin8U_d7Cz4S5VqAJkx0CKDDTPImjvpB4VxmiegLT2OCuZK9ZPXOzljZ1yiftvR_JoZDHXf2WawP-W-BvlWOwtsXf6lJOFW39i29PMKwCIMaPfq9FC-8zMtI3o8u0TRKjKgHR1PwKUXyRPo-ImfdorVd-J0mmuJQWeNa-0bECTzuPnaL4x1Lf8QG1IOeZjin7UzgDSsahJyrilV7gSkO9kocZuqvbMRl37OZjg_fHowK19Khq22UBUcTdh9kFwkvi83J_M2EakQ"
        }
        "#).expect("parsed jwk");
        assert_eq!(
            String::from("cA88WX2aDbX8LcxByNm2UA=="),
            code.hash(&rsa_key).unwrap()
        );
    }
}
