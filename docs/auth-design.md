# Auth design note (IdP expansion)

This note describes the supported authentication flows, configuration shape, and token caching/refresh behavior used by toppy.

## Supported flows

1. **Static token/JWT**
   - Use a pre-issued token in config.
   - No login step required.

2. **OIDC device-code**
   - CLI displays verification URL + user code.
   - User completes login at IdP on another device.
   - CLI polls token endpoint until success or expiry.

3. **OIDC auth-code + PKCE (browser-based)**
   - CLI prints an authorization URL and starts a local redirect listener.
   - Browser login returns an auth code to `redirect_uri`.
   - CLI exchanges code + PKCE verifier for tokens.

4. **SAML via broker (federation)**
   - CLI uses OIDC device-code against a broker IdP.
   - Broker handles SAML federation and issues OIDC tokens.

## Configuration shapes

### Token

```toml
[auth]
mode = "token"
token = "..."
```

### OIDC device-code

```toml
[auth]
mode = "oidc_device_code"
issuer = "https://issuer.example"
client_id = "toppy-cli"
audience = "toppy"              # optional
scope = "openid offline_access" # optional
# token_cache_path = "/path/to/oidc-token.json" # optional
```

### OIDC auth-code + PKCE

```toml
[auth]
mode = "oidc_auth_code_pkce"
issuer = "https://issuer.example"
client_id = "toppy-cli"
audience = "toppy"               # optional
scope = "openid offline_access"  # optional
redirect_uri = "http://127.0.0.1:8080/callback"
# token_cache_path = "/path/to/oidc-auth-code-token.json" # optional
```

### SAML via broker

```toml
[auth]
mode = "saml"
idp_entity_id = "https://idp.example/saml"
sp_entity_id = "toppy-sp"               # optional
broker_issuer = "https://broker.example"
broker_client_id = "toppy-cli"
broker_audience = "toppy"               # optional
broker_scope = "openid offline_access"  # optional
# token_cache_path = "/path/to/saml-token.json" # optional
```

## Token cache and refresh

- Tokens are cached locally in JSON (path configurable per mode).
- `toppy doctor` and `toppy udp`/`up` resolve tokens from cache.
- If access tokens are expired and a refresh token exists, the CLI refreshes automatically.
- If no refresh token is available, re-run `toppy login`.

## UX notes

- CLI never prints tokens unless `--print-token` is explicitly set.
- PKCE flow verifies the `state` parameter on redirect.
- Ensure `redirect_uri` is registered at the IdP.
