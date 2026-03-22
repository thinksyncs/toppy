use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthIdentity {
    pub subject: Option<String>,
    pub claims: BTreeMap<String, String>,
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

pub fn extract_jwt_identity(token: &str) -> Result<AuthIdentity, String> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| "token is not a JWT".to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("jwt payload decode failed: {}", e))?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| format!("jwt payload parse failed: {}", e))?;
    let claims_obj = claims
        .as_object()
        .ok_or_else(|| "jwt payload must be a JSON object".to_string())?;

    let mut extracted = AuthIdentity::default();
    for (key, value) in claims_obj {
        let Some(text) = claim_value_as_string(value) else {
            continue;
        };
        if key == "sub" {
            extracted.subject = Some(text.clone());
        }
        extracted.claims.insert(key.clone(), text);
    }

    Ok(extracted)
}

fn claim_value_as_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
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

    #[test]
    fn extract_jwt_identity_reads_subject_and_scalar_claims() {
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

        let identity = extract_jwt_identity(&token).expect("extract");
        assert_eq!(identity.subject.as_deref(), Some("user-123"));
        assert_eq!(identity.claims.get("iss").map(String::as_str), Some("https://issuer.example"));
        assert_eq!(identity.claims.get("aud").map(String::as_str), Some("toppy"));
    }
}
