use std::env;
use toppy_core::auth::{validate_jwt_hs256, JwtConfig};

#[derive(Clone)]
pub(crate) enum AuthMode {
    None,
    SharedToken(String),
    Jwt(JwtConfig),
}

impl AuthMode {
    pub(crate) fn from_env() -> Result<Self, String> {
        let jwt_secret = env::var("TOPPY_GW_JWT_SECRET").ok();
        let jwt_issuer = env::var("TOPPY_GW_JWT_ISS").ok();
        let jwt_audience = env::var("TOPPY_GW_JWT_AUD").ok();
        let shared_token = env::var("TOPPY_GW_TOKEN").ok();

        if let Some(secret) = jwt_secret {
            return Ok(AuthMode::Jwt(JwtConfig {
                secret,
                issuer: jwt_issuer,
                audience: jwt_audience,
            }));
        }

        if let Some(token) = shared_token {
            return Ok(AuthMode::SharedToken(token));
        }

        Ok(AuthMode::None)
    }

    pub(crate) fn validate(&self, token: Option<&str>) -> Result<(), String> {
        match self {
            AuthMode::None => Ok(()),
            AuthMode::SharedToken(expected) => match token {
                Some(value) if value == expected => Ok(()),
                _ => Err("missing or invalid token".to_string()),
            },
            AuthMode::Jwt(cfg) => {
                let token = token.ok_or_else(|| "missing jwt token".to_string())?;
                validate_jwt_hs256(token, cfg)
            }
        }
    }
}
