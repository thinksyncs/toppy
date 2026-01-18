use quinn::crypto::rustls::QuicServerConfig;
use quinn::ServerConfig;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server, StatusCode};
use toppy_core::auth::{validate_jwt_hs256, JwtConfig};

use bytes::Bytes;
use h3::ext::Protocol;
use http::StatusCode as HttpStatusCode;

fn main() {
    let http_listen = env::var("TOPPY_GW_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let quic_listen =
        env::var("TOPPY_GW_QUIC_LISTEN").unwrap_or_else(|_| "0.0.0.0:4433".to_string());

    let http_thread = thread::spawn(move || run_healthz(&http_listen));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("failed to start tokio runtime: {}", e);
            std::process::exit(1);
        });
    runtime.block_on(async move {
        if let Err(e) = run_quic(&quic_listen).await {
            eprintln!("quic server error: {}", e);
        }
    });

    let _ = http_thread.join();
}

fn run_healthz(listen: &str) {
    let server = Server::http(listen).unwrap_or_else(|e| {
        eprintln!("failed to start gateway on {}: {}", listen, e);
        std::process::exit(1);
    });

    println!("toppy-gw http listening on {}", listen);

    for request in server.incoming_requests() {
        if request.method() == &Method::Get && request.url() == "/healthz" {
            let mut response = Response::from_string("{\"status\":\"ok\"}\n");
            response.add_header(
                Header::from_bytes("content-type", "application/json").expect("header"),
            );
            response.add_header(Header::from_bytes("cache-control", "no-store").expect("header"));
            let _ = request.respond(response.with_status_code(StatusCode(200)));
            continue;
        }

        let response = Response::from_string("not found\n").with_status_code(StatusCode(404));
        let _ = request.respond(response);
    }
}

#[derive(Clone)]
enum AuthMode {
    None,
    SharedToken(String),
    Jwt(JwtConfig),
}

impl AuthMode {
    fn from_env() -> Result<Self, String> {
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

    fn validate(&self, token: Option<&str>) -> Result<(), String> {
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

async fn run_quic(listen: &str) -> Result<(), String> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid quic listen {}: {}", listen, e))?;
    let cert_path = env::var("TOPPY_GW_CERT").ok();
    let key_path = env::var("TOPPY_GW_KEY").ok();
    let auth_mode = AuthMode::from_env()?;
    let server_config = build_quic_config(cert_path.as_deref(), key_path.as_deref())?;
    let endpoint = quinn::Endpoint::server(server_config, addr)
        .map_err(|e| format!("quic bind failed: {}", e))?;

    println!("toppy-gw quic listening on {}", listen);

    while let Some(incoming) = endpoint.accept().await {
        let auth_mode = auth_mode.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(e) = handle_connection(connection, auth_mode).await {
                        eprintln!("quic connection error: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("quic accept failed: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    connection: quinn::Connection,
    auth_mode: AuthMode,
) -> Result<(), String> {
    let is_h3 = connection
        .handshake_data()
        .and_then(|any| any.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.protocol)
        .as_deref()
        == Some(b"h3");

    if is_h3 {
        handle_h3_connection(connection, auth_mode).await
    } else {
        handle_ping_connection(connection, auth_mode).await
    }
}

async fn handle_ping_connection(
    connection: quinn::Connection,
    auth_mode: AuthMode,
) -> Result<(), String> {
    loop {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| format!("quic stream accept failed: {}", e))?;

        let data = recv
            .read_to_end(256)
            .await
            .map_err(|e| format!("quic read failed: {}", e))?;
        if !data.starts_with(b"ping") {
            let _ = send.finish();
            continue;
        }
        let token = if data == b"ping" {
            None
        } else {
            data.strip_prefix(b"ping ")
        };
        let provided = token
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(|value| value.trim());
        if let Err(err) = auth_mode.validate(provided) {
            eprintln!("token rejected: {}", err);
            send.write_all(b"unauthorized")
                .await
                .map_err(|e| format!("quic write failed: {}", e))?;
            let _ = send.finish();
            continue;
        }
        send.write_all(b"pong")
            .await
            .map_err(|e| format!("quic write failed: {}", e))?;
        let _ = send.finish();
    }
}

async fn handle_h3_connection(
    connection: quinn::Connection,
    auth_mode: AuthMode,
) -> Result<(), String> {
    let quinn_conn = h3_quinn::Connection::new(connection);
    let mut server_builder = h3::server::builder();
    server_builder.enable_extended_connect(true);
    let mut h3_conn = server_builder
        .build::<_, Bytes>(quinn_conn)
        .await
        .map_err(|e| format!("h3 accept failed: {e:?}"))?;

    while let Some(resolver) = h3_conn
        .accept()
        .await
        .map_err(|e| format!("h3 accept request failed: {e:?}"))?
    {
        let (req, mut stream) = resolver
            .resolve_request()
            .await
            .map_err(|e| format!("h3 resolve request failed: {e:?}"))?;
        let is_connect = req.method() == http::Method::CONNECT;
        let protocol = req.extensions().get::<Protocol>().copied();

        if !is_connect || protocol != Some(Protocol::CONNECT_UDP) {
            let res = http::Response::builder()
                .status(HttpStatusCode::NOT_FOUND)
                .body(())
                .map_err(|e| format!("h3 response build failed: {e}"))?;
            stream
                .send_response(res)
                .await
                .map_err(|e| format!("h3 send response failed: {e:?}"))?;
            let _ = stream.finish().await;
            continue;
        }

        let authz = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        let token = authz
            .and_then(|v| v.strip_prefix("Bearer ").or(Some(v)))
            .map(|v| v.trim());
        if let Err(err) = auth_mode.validate(token) {
            let res = http::Response::builder()
                .status(HttpStatusCode::UNAUTHORIZED)
                .body(())
                .map_err(|e| format!("h3 response build failed: {e}"))?;
            stream
                .send_response(res)
                .await
                .map_err(|e| format!("h3 send response failed: {e:?}"))?;
            let _ = stream.finish().await;
            eprintln!("connect-udp unauthorized: {err}");
            continue;
        }

        // Minimal CONNECT-UDP handshake: accept the request.
        let res = http::Response::builder()
            .status(HttpStatusCode::OK)
            .body(())
            .map_err(|e| format!("h3 response build failed: {e}"))?;
        stream
            .send_response(res)
            .await
            .map_err(|e| format!("h3 send response failed: {e:?}"))?;

        // Keep the stream open until the peer closes it.
        while let Some(_chunk) = stream
            .recv_data()
            .await
            .map_err(|e| format!("h3 recv data failed: {e:?}"))?
        {
            // CONNECT-UDP payload is carried in HTTP Datagrams, not stream data.
        }
        let _ = stream.finish().await;
    }

    Ok(())
}

fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = fs::read(path).map_err(|e| format!("failed to read cert {}: {}", path, e))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certs {}: {}", path, e))?;
    if certs.is_empty() {
        return Err(format!("no certs found in {}", path));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let data = fs::read(path).map_err(|e| format!("failed to read key {}: {}", path, e))?;
    match PrivateKeyDer::from_pem_slice(&data) {
        Ok(key) => Ok(key),
        Err(PemError::NoItemsFound) => Err(format!("no private key found in {}", path)),
        Err(err) => Err(format!("failed to parse key {}: {}", path, err)),
    }
}

fn build_quic_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<ServerConfig, String> {
    let (cert_chain, key) = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            (load_cert_chain(cert_path)?, load_private_key(key_path)?)
        }
        (None, None) => {
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| format!("cert generation failed: {}", e))?;
            let cert_der = cert.der().clone();
            let key_der = key_pair.serialize_der();
            (
                vec![cert_der],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
        }
        _ => {
            return Err(
                "both TOPPY_GW_CERT and TOPPY_GW_KEY must be set to load external certs"
                    .to_string(),
            )
        }
    };

    let mut rustls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| e.to_string())?;
    // Enable HTTP/3 ALPN. Non-H3 clients can still connect without ALPN.
    rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| format!("quic server crypto config failed: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .map_err(|_| "invalid idle timeout".to_string())?,
    ));
    server_config.transport = Arc::new(transport);
    Ok(server_config)
}
