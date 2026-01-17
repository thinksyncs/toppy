use std::env;
use tiny_http::{Header, Method, Response, Server, StatusCode};

fn main() {
    let listen = env::var("TOPPY_GW_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let server = Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("failed to start gateway on {}: {}", listen, e);
        std::process::exit(1);
    });

    println!("toppy-gw listening on {}", listen);

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
