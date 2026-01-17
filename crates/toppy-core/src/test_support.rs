use std::sync::Mutex;

// Shared lock for tests that touch process-wide environment variables.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());
