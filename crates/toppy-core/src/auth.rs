use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

pub fn validate_jwt_hs256(token: &str, cfg: &JwtConfig) -> Result<(), String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    if let Some(issuer) = cfg.issuer.as_deref() {
        validation.set_issuer(&[issuer]);
    }
    if let Some(audience) = cfg.audience.as_deref() {
        validation.set_audience(&[audience]);
    }

    decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(cfg.secret.as_bytes()),
        &validation,
    )
    .map(|_| ())
    .map_err(|e| format!("jwt validation failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: usize,
    }

    fn now_secs() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as usize
    }

    #[test]
    fn jwt_validation_accepts_valid_token() {
        let claims = TestClaims {
            sub: "user-123".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: "toppy".to_string(),
            exp: now_secs() + 60,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("encode");

        let cfg = JwtConfig {
            secret: "secret".to_string(),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("toppy".to_string()),
        };

        validate_jwt_hs256(&token, &cfg).expect("valid token");
    }

    #[test]
    fn jwt_validation_rejects_bad_secret() {
        let claims = TestClaims {
            sub: "user-123".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: "toppy".to_string(),
            exp: now_secs() + 60,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("encode");

        let cfg = JwtConfig {
            secret: "wrong".to_string(),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("toppy".to_string()),
        };

        let err = validate_jwt_hs256(&token, &cfg).unwrap_err();
        assert!(err.contains("jwt validation failed"));
    }

    #[test]
    fn jwt_validation_rejects_expired_token() {
        let claims = TestClaims {
            sub: "user-123".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: "toppy".to_string(),
            exp: now_secs().saturating_sub(3600),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("encode");

        let cfg = JwtConfig {
            secret: "secret".to_string(),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("toppy".to_string()),
        };

        let err = validate_jwt_hs256(&token, &cfg).unwrap_err();
        assert!(err.contains("jwt validation failed"));
    }
}
