use quinn::crypto::rustls::QuicServerConfig;
use quinn::ServerConfig;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

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

pub(crate) fn build_quic_config(
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
