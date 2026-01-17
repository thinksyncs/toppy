use quinn::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server, StatusCode};

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

async fn run_quic(listen: &str) -> Result<(), String> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid quic listen {}: {}", listen, e))?;
    let server_config = build_quic_config()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)
        .map_err(|e| format!("quic bind failed: {}", e))?;

    println!("toppy-gw quic listening on {}", listen);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(e) = handle_connection(connection).await {
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

async fn handle_connection(connection: quinn::Connection) -> Result<(), String> {
    loop {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| format!("quic stream accept failed: {}", e))?;

        let data = recv
            .read_to_end(16)
            .await
            .map_err(|e| format!("quic read failed: {}", e))?;
        if data == b"ping" {
            send.write_all(b"pong")
                .await
                .map_err(|e| format!("quic write failed: {}", e))?;
        }
        let _ = send.finish();
    }
}

fn build_quic_config() -> Result<ServerConfig, String> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| format!("cert generation failed: {}", e))?;
    let cert_der = cert.der().clone();
    let key_der = key_pair.serialize_der();

    let cert_chain = vec![cert_der];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let mut server_config =
        quinn::ServerConfig::with_single_cert(cert_chain, key).map_err(|e| e.to_string())?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .map_err(|_| "invalid idle timeout".to_string())?,
    ));
    server_config.transport = Arc::new(transport);
    Ok(server_config)
}
