use crate::auth::AuthMode;
use bytes::Bytes;
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::StatusCode as HttpStatusCode;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use toppy_core::rate::TokenBucket;
use toppy_proto::masque::{HttpDatagram, CONNECT_UDP_CONTEXT_ID};

pub(crate) async fn handle_h3_connection(
    connection: quinn::Connection,
    auth_mode: AuthMode,
) -> Result<(), String> {
    let quinn_conn = h3_quinn::Connection::new(connection);
    let mut server_builder = h3::server::builder();
    server_builder.enable_extended_connect(true);
    server_builder.enable_datagram(true);
    let mut h3_conn = server_builder
        .build::<_, Bytes>(quinn_conn)
        .await
        .map_err(|e| format!("h3 accept failed: {e:?}"))?;

    let udp_rate_limit = gw_udp_rate_limit_from_env();
    let mut datagram_routes: HashMap<
        h3::quic::StreamId,
        tokio::sync::mpsc::UnboundedSender<Bytes>,
    > = HashMap::new();
    let (session_done_tx, mut session_done_rx) =
        tokio::sync::mpsc::unbounded_channel::<ConnectUdpSessionDone>();
    let mut dg_reader = h3_conn.get_datagram_reader();

    loop {
        tokio::select! {
            accept = h3_conn.accept() => {
                let Some(resolver) = accept
                    .map_err(|e| format!("h3 accept request failed: {e:?}"))?
                else {
                    break;
                };

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

                let mode = ConnectUdpMode::from_uri(req.uri());
                let target = match mode {
                    ConnectUdpMode::Echo => None,
                    ConnectUdpMode::Forward => match parse_connect_udp_target(req.uri()).await {
                        Ok(addr) => Some(addr),
                        Err(err) => {
                            let res = http::Response::builder()
                                .status(HttpStatusCode::BAD_REQUEST)
                                .body(())
                                .map_err(|e| format!("h3 response build failed: {e}"))?;
                            stream
                                .send_response(res)
                                .await
                                .map_err(|e| format!("h3 send response failed: {e:?}"))?;
                            let _ = stream.finish().await;
                            eprintln!("connect-udp bad request: {err}");
                            continue;
                        }
                    },
                };

                let res = http::Response::builder()
                    .status(HttpStatusCode::OK)
                    .body(())
                    .map_err(|e| format!("h3 response build failed: {e}"))?;
                stream
                    .send_response(res)
                    .await
                    .map_err(|e| format!("h3 send response failed: {e:?}"))?;

                let udp = if let Some(target_addr) = target {
                    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0")
                        .await
                        .map_err(|e| format!("udp bind failed: {e}"))?;
                    udp.connect(target_addr)
                        .await
                        .map_err(|e| format!("udp connect failed: {e}"))?;
                    Some(udp)
                } else {
                    None
                };

                let stream_id = stream.id();
                let mut dg_sender = h3_conn.get_datagram_sender(stream_id);
                let (session_tx, mut session_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
                datagram_routes.insert(stream_id, session_tx);
                let done_tx = session_done_tx.clone();

                tokio::spawn(async move {
                    let started_at = std::time::Instant::now();
                    let mut ingress_limiter = gw_udp_limiter(udp_rate_limit);
                    let mut egress_limiter = gw_udp_limiter(udp_rate_limit);
                    let mut ingress_datagrams = 0u64;
                    let mut egress_datagrams = 0u64;
                    let mut ingress_rate_drops = 0u64;
                    let mut egress_rate_drops = 0u64;
                    let mut buf = vec![0u8; 2048];

                    loop {
                        tokio::select! {
                            maybe_payload = session_rx.recv() => {
                                let Some(payload) = maybe_payload else {
                                    break;
                                };
                                ingress_datagrams = ingress_datagrams.saturating_add(1);
                                if !gw_udp_datagram_allowed(&mut ingress_limiter, payload.len(), started_at) {
                                    ingress_rate_drops = ingress_rate_drops.saturating_add(1);
                                    continue;
                                }

                                match mode {
                                    ConnectUdpMode::Echo => {
                                        if let Err(err) = dg_sender.send_datagram(payload) {
                                            eprintln!("connect-udp echo send failed on {:?}: {}", stream_id, err);
                                            break;
                                        }
                                    }
                                    ConnectUdpMode::Forward => {
                                        let decoded = match HttpDatagram::decode(payload.as_ref()) {
                                            Ok(decoded) => decoded,
                                            Err(_) => continue,
                                        };
                                        if decoded.context_id != CONNECT_UDP_CONTEXT_ID {
                                            continue;
                                        }
                                        if let Some(udp) = udp.as_ref() {
                                            if let Err(err) = udp.send(decoded.payload.as_slice()).await {
                                                eprintln!("udp send failed on {:?}: {}", stream_id, err);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            n = async {
                                match udp.as_ref() {
                                    Some(udp) => udp.recv(&mut buf).await.map(Some),
                                    None => std::future::pending::<Result<Option<usize>, std::io::Error>>().await,
                                }
                            } => {
                                let n = match n {
                                    Ok(Some(n)) => n,
                                    Ok(None) => continue,
                                    Err(err) => {
                                        eprintln!("udp recv failed on {:?}: {}", stream_id, err);
                                        break;
                                    }
                                };

                                egress_datagrams = egress_datagrams.saturating_add(1);
                                if !gw_udp_datagram_allowed(&mut egress_limiter, n, started_at) {
                                    egress_rate_drops = egress_rate_drops.saturating_add(1);
                                    continue;
                                }

                                let dg = match HttpDatagram::new(CONNECT_UDP_CONTEXT_ID, &buf[..n]).encode() {
                                    Ok(dg) => dg,
                                    Err(_) => continue,
                                };
                                if let Err(err) = dg_sender.send_datagram(Bytes::from(dg)) {
                                    eprintln!("h3 send datagram failed on {:?}: {}", stream_id, err);
                                    break;
                                }
                            }
                            chunk = stream.recv_data() => {
                                match chunk {
                                    Ok(Some(_)) => {}
                                    Ok(None) => break,
                                    Err(err) => {
                                        eprintln!("h3 recv data failed on {:?}: {:?}", stream_id, err);
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    let _ = stream.finish().await;
                    let _ = done_tx.send(ConnectUdpSessionDone {
                        stream_id,
                        mode,
                        target,
                        ingress_datagrams,
                        egress_datagrams,
                        ingress_rate_drops,
                        egress_rate_drops,
                    });
                });
            }
            dg = dg_reader.read_datagram() => {
                let dg = dg.map_err(|e| format!("h3 recv datagram failed: {e:?}"))?;
                if let Some(tx) = datagram_routes.get(&dg.stream_id()) {
                    let _ = tx.send(dg.into_payload());
                }
            }
            Some(done) = session_done_rx.recv() => {
                datagram_routes.remove(&done.stream_id);
                eprintln!(
                    "connect-udp session ended: stream_id={:?} mode={:?} target={:?} ingress_datagrams={} egress_datagrams={} ingress_rate_drops={} egress_rate_drops={}",
                    done.stream_id,
                    done.mode,
                    done.target,
                    done.ingress_datagrams,
                    done.egress_datagrams,
                    done.ingress_rate_drops,
                    done.egress_rate_drops,
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectUdpMode {
    Echo,
    Forward,
}

#[derive(Debug, Clone, Copy)]
struct GwUdpRateLimit {
    bytes_per_sec: u64,
    burst_bytes: u64,
}

#[derive(Debug)]
struct ConnectUdpSessionDone {
    stream_id: h3::quic::StreamId,
    mode: ConnectUdpMode,
    target: Option<SocketAddr>,
    ingress_datagrams: u64,
    egress_datagrams: u64,
    ingress_rate_drops: u64,
    egress_rate_drops: u64,
}

fn gw_udp_rate_limit_from_env() -> Option<GwUdpRateLimit> {
    let bytes_per_sec = env::var("TOPPY_GW_UDP_BYTES_PER_SEC")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)?;
    let burst_bytes = env::var("TOPPY_GW_UDP_BURST_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(bytes_per_sec);
    Some(GwUdpRateLimit {
        bytes_per_sec,
        burst_bytes,
    })
}

fn gw_udp_limiter(limit: Option<GwUdpRateLimit>) -> Option<TokenBucket> {
    limit.map(|limit| TokenBucket::new(limit.burst_bytes, limit.bytes_per_sec))
}

fn gw_udp_datagram_allowed(
    bucket: &mut Option<TokenBucket>,
    bytes: usize,
    started_at: std::time::Instant,
) -> bool {
    match bucket.as_mut() {
        Some(bucket) => bucket.try_take(bytes as u64, started_at.elapsed()),
        None => true,
    }
}

impl ConnectUdpMode {
    fn from_uri(uri: &http::Uri) -> Self {
        if uri.path().starts_with("/.well-known/masque/udp-forward/") {
            Self::Forward
        } else {
            Self::Echo
        }
    }
}

async fn parse_connect_udp_target(uri: &http::Uri) -> Result<SocketAddr, String> {
    let path = uri.path();
    if !path.starts_with("/.well-known/masque/udp-forward/") {
        return Err("connect-udp forwarding requires /.well-known/masque/udp-forward/".to_string());
    }
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return Err("connect-udp path too short".to_string());
    }

    let port_str = segments
        .pop()
        .ok_or_else(|| "missing connect-udp port".to_string())?;
    let host = segments
        .pop()
        .ok_or_else(|| "missing connect-udp host".to_string())?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid connect-udp port: {port_str}"))?;

    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("dns lookup failed for {host}:{port}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| format!("dns lookup returned no addresses for {host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn connect_udp_mode_uses_forward_prefix() {
        let forward: http::Uri = "https://example/.well-known/masque/udp-forward/127.0.0.1/53/"
            .parse()
            .expect("forward uri");
        let echo: http::Uri = "https://example/.well-known/masque/udp/127.0.0.1/53/"
            .parse()
            .expect("echo uri");

        assert_eq!(ConnectUdpMode::from_uri(&forward), ConnectUdpMode::Forward);
        assert_eq!(ConnectUdpMode::from_uri(&echo), ConnectUdpMode::Echo);
    }

    #[test]
    fn gw_udp_rate_limit_from_env_uses_default_burst() {
        let _guard = toppy_core::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev_rate = env::var("TOPPY_GW_UDP_BYTES_PER_SEC").ok();
        let prev_burst = env::var("TOPPY_GW_UDP_BURST_BYTES").ok();
        env::set_var("TOPPY_GW_UDP_BYTES_PER_SEC", "2048");
        env::remove_var("TOPPY_GW_UDP_BURST_BYTES");

        let limit = gw_udp_rate_limit_from_env().expect("limit");
        assert_eq!(limit.bytes_per_sec, 2048);
        assert_eq!(limit.burst_bytes, 2048);

        if let Some(value) = prev_rate {
            env::set_var("TOPPY_GW_UDP_BYTES_PER_SEC", value);
        } else {
            env::remove_var("TOPPY_GW_UDP_BYTES_PER_SEC");
        }
        if let Some(value) = prev_burst {
            env::set_var("TOPPY_GW_UDP_BURST_BYTES", value);
        } else {
            env::remove_var("TOPPY_GW_UDP_BURST_BYTES");
        }
    }

    #[test]
    fn gw_udp_datagram_allowed_respects_capacity() {
        let mut bucket = gw_udp_limiter(Some(GwUdpRateLimit {
            bytes_per_sec: 1,
            burst_bytes: 3,
        }));
        let started_at = Instant::now();

        assert!(gw_udp_datagram_allowed(&mut bucket, 3, started_at));
        assert!(!gw_udp_datagram_allowed(&mut bucket, 1, started_at));
    }

    #[tokio::test]
    async fn parse_connect_udp_target_accepts_socket_addr_fast_path() {
        let uri: http::Uri = "https://example/.well-known/masque/udp-forward/127.0.0.1/5353/"
            .parse()
            .expect("uri");

        let target = parse_connect_udp_target(&uri).await.expect("target");
        assert_eq!(
            target,
            "127.0.0.1:5353".parse::<SocketAddr>().expect("addr")
        );
    }

    #[tokio::test]
    async fn parse_connect_udp_target_rejects_invalid_path() {
        let uri: http::Uri = "https://example/.well-known/masque/udp/127.0.0.1/5353/"
            .parse()
            .expect("uri");

        let err = parse_connect_udp_target(&uri).await.unwrap_err();
        assert!(err.contains("udp-forward"));
    }
}
