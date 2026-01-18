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

fn write_config_with_policy(path: &PathBuf) {
    let data = r#"gateway = "127.0.0.1"
port = 4433
mtu = 1350

[policy]
  [[policy.allow]]
  cidr = "127.0.0.1/32"
  ports = [2222]
"#;
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

#[test]
fn doctor_reports_policy_denied_reason() {
    let _guard = toppy_core::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let path = unique_temp_path("doctor-policy-denied");
    write_config_with_policy(&path);
    let prev = env::var("TOPPY_CONFIG").ok();
    let prev_net = env::var("TOPPY_DOCTOR_NET").ok();
    let prev_tun = env::var("TOPPY_DOCTOR_TUN").ok();
    let prev_target = env::var("TOPPY_DOCTOR_TARGET").ok();
    env::set_var("TOPPY_CONFIG", &path);
    env::set_var("TOPPY_DOCTOR_NET", "skip");
    env::set_var("TOPPY_DOCTOR_TUN", "pass");
    env::set_var("TOPPY_DOCTOR_TARGET", "127.0.0.1:2223");

    let report = doctor_check();
    let policy_check = report.checks.iter().find(|c| c.id == "policy.denied");
    assert!(policy_check.is_some());
    let policy_check = policy_check.expect("policy.denied");
    assert_eq!(policy_check.status, "fail");
    assert!(policy_check.summary.contains("not allowed"));

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
    if let Some(value) = prev_target {
        env::set_var("TOPPY_DOCTOR_TARGET", value);
    } else {
        env::remove_var("TOPPY_DOCTOR_TARGET");
    }
    let _ = fs::remove_file(&path);
}
