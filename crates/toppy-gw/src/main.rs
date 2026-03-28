mod auth;
mod connect_udp;
mod healthz;
mod routing;
mod tls;

use std::env;
use std::thread;

fn main() {
    let http_listen = env::var("TOPPY_GW_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let quic_listen =
        env::var("TOPPY_GW_QUIC_LISTEN").unwrap_or_else(|_| "0.0.0.0:4433".to_string());

    let http_thread = thread::spawn(move || healthz::run(&http_listen));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("failed to start tokio runtime: {}", e);
            std::process::exit(1);
        });
    runtime.block_on(async move {
        if let Err(e) = routing::run_quic(&quic_listen).await {
            eprintln!("quic server error: {}", e);
        }
    });

    let _ = http_thread.join();
}
