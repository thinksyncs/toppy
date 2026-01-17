//! Tests for the `doctor` module.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use toppy_core::doctor::doctor_check;

fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    env::temp_dir().join(format!("toppy-{prefix}-{nanos}.toml"))
}

fn write_config(path: &PathBuf, host: &str, port: u16) {
    let data = format!(
        "gateway = \"{}\"\nport = {}\nmtu = 1350\n",
        host.replace('"', "\\\""),
        port
    );
    fs::write(path, data).expect("write config");
}

#[test]
fn doctor_passes_when_config_and_network_ok() {
    let _guard = toppy_core::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let path = unique_temp_path("doctor-pass");
    write_config(&path, "127.0.0.1", 4433);
    let prev = env::var("TOPPY_CONFIG").ok();
    let prev_net = env::var("TOPPY_DOCTOR_NET").ok();
    let prev_tun = env::var("TOPPY_DOCTOR_TUN").ok();
    env::set_var("TOPPY_CONFIG", &path);
    env::set_var("TOPPY_DOCTOR_NET", "pass");
    env::set_var("TOPPY_DOCTOR_TUN", "pass");

    let report = doctor_check();
    assert_eq!(report.overall, "pass");
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "cfg.load" && c.status == "pass"));
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "net.dns" && c.status == "pass"));
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "h3.connect" && c.status == "pass"));

    if let Some(value) = prev {
        env::set_var("TOPPY_CONFIG", value);
    } else {
        env::remove_var("TOPPY_CONFIG");
    }
    if let Some(value) = prev_net {
        env::set_var("TOPPY_DOCTOR_NET", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_NET");
    }
    if let Some(value) = prev_tun {
        env::set_var("TOPPY_DOCTOR_TUN", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_TUN");
    }
    let _ = fs::remove_file(&path);
}

#[test]
fn doctor_warns_when_config_missing() {
    let _guard = toppy_core::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let path = unique_temp_path("doctor-missing");
    let prev = env::var("TOPPY_CONFIG").ok();
    let prev_net = env::var("TOPPY_DOCTOR_NET").ok();
    let prev_tun = env::var("TOPPY_DOCTOR_TUN").ok();
    env::set_var("TOPPY_CONFIG", &path);
    env::set_var("TOPPY_DOCTOR_NET", "pass");
    env::set_var("TOPPY_DOCTOR_TUN", "pass");

    let report = doctor_check();
    assert_eq!(report.overall, "fail");
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "cfg.load" && c.status == "fail"));
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "net.dns" && c.status == "warn"));
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "h3.connect" && c.status == "warn"));

    if let Some(value) = prev {
        env::set_var("TOPPY_CONFIG", value);
    } else {
        env::remove_var("TOPPY_CONFIG");
    }
    if let Some(value) = prev_net {
        env::set_var("TOPPY_DOCTOR_NET", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_NET");
    }
    if let Some(value) = prev_tun {
        env::set_var("TOPPY_DOCTOR_TUN", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_TUN");
    }
}

#[test]
fn doctor_report_includes_version() {
    let _guard = toppy_core::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let path = unique_temp_path("doctor-version");
    let prev = env::var("TOPPY_CONFIG").ok();
    let prev_net = env::var("TOPPY_DOCTOR_NET").ok();
    let prev_tun = env::var("TOPPY_DOCTOR_TUN").ok();
    env::set_var("TOPPY_CONFIG", &path);
    env::set_var("TOPPY_DOCTOR_NET", "pass");
    env::set_var("TOPPY_DOCTOR_TUN", "pass");

    let report = doctor_check();
    assert_eq!(report.version, env!("CARGO_PKG_VERSION"));

    if let Some(value) = prev {
        env::set_var("TOPPY_CONFIG", value);
    } else {
        env::remove_var("TOPPY_CONFIG");
    }
    if let Some(value) = prev_net {
        env::set_var("TOPPY_DOCTOR_NET", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_NET");
    }
    if let Some(value) = prev_tun {
        env::set_var("TOPPY_DOCTOR_TUN", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_TUN");
    }
}
