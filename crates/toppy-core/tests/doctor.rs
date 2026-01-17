//! Tests for the `doctor` module.

use toppy_core::doctor::{doctor_check, DoctorCheck};

#[test]
fn doctor_overall_fails_if_any_check_fails() {
    let report = doctor_check();
    // Since the placeholder implementation includes a failing check, overall should be "fail".
    assert_eq!(report.overall, "fail");
    assert!(report.checks.iter().any(|c| c.status == "fail"));
}

#[test]
fn doctor_report_has_expected_checks() {
    let report = doctor_check();
    // Ensure that at least one cfg.load and net.h3 check exists in the report.
    let mut found_cfg = false;
    let mut found_net = false;
    for c in &report.checks {
        if c.id == "cfg.load" {
            found_cfg = true;
        } else if c.id == "net.h3" {
            found_net = true;
        }
    }
    assert!(found_cfg, "Expected cfg.load check in doctor report");
    assert!(found_net, "Expected net.h3 check in doctor report");
}