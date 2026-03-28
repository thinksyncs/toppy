use crate::auth::AuthMode;
use crate::connect_udp::handle_h3_connection;
use crate::tls::build_quic_config;
use std::env;
use std::net::SocketAddr;

pub(crate) async fn run_quic(listen: &str) -> Result<(), String> {
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
