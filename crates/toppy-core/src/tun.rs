#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunProbeStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct TunProbe {
    pub status: TunProbeStatus,
    pub summary: String,
}

impl TunProbe {
    pub fn pass(summary: impl Into<String>) -> Self {
        TunProbe {
            status: TunProbeStatus::Pass,
            summary: summary.into(),
        }
    }

    pub fn warn(summary: impl Into<String>) -> Self {
        TunProbe {
            status: TunProbeStatus::Warn,
            summary: summary.into(),
        }
    }

    pub fn fail(summary: impl Into<String>) -> Self {
        TunProbe {
            status: TunProbeStatus::Fail,
            summary: summary.into(),
        }
    }
}

#[cfg(target_os = "windows")]
pub fn windows_wintun_check() -> TunProbe {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn env_path(key: &str) -> Option<PathBuf> {
        match env::var(key) {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(trimmed))
                }
            }
            Err(_) => None,
        }
    }

    fn load_from_path(path: &Path) -> Result<(wintun::Wintun, String), String> {
        if !path.exists() {
            return Err(format!("wintun.dll not found at {}", path.display()));
        }
        unsafe { wintun::load_from_path(path) }
            .map(|wintun| (wintun, format!("wintun.dll at {}", path.display())))
            .map_err(|err| format!("failed to load {}: {}", path.display(), err))
    }

    fn load_wintun() -> Result<(wintun::Wintun, String), String> {
        if let Some(path) = env_path("TOPPY_WINTUN_DLL") {
            return load_from_path(&path);
        }
        if let Some(dir) = env_path("TOPPY_WINTUN_DIR") {
            return load_from_path(&dir.join("wintun.dll"));
        }
        if let Ok(exe) = env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("wintun.dll");
                if candidate.exists() {
                    return load_from_path(&candidate);
                }
            }
        }
        unsafe { wintun::load() }
            .map(|wintun| (wintun, "wintun.dll in current directory".to_string()))
            .map_err(|err| format!("failed to load wintun.dll: {}", err))
    }

    fn delete_adapter(adapter: Arc<wintun::Adapter>) -> Result<bool, String> {
        match Arc::try_unwrap(adapter) {
            Ok(adapter) => adapter
                .delete()
                .map(|_| true)
                .map_err(|err| format!("delete failed: {}", err)),
            Err(adapter) => {
                drop(adapter);
                Ok(false)
            }
        }
    }

    let (wintun, source) = match load_wintun() {
        Ok(result) => result,
        Err(err) => {
            return TunProbe::fail(format!(
                "wintun.dll load failed: {} (set TOPPY_WINTUN_DLL or TOPPY_WINTUN_DIR)",
                err
            ))
        }
    };

    let adapter_name = env::var("TOPPY_WINTUN_ADAPTER")
        .ok()
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .unwrap_or_else(|| "toppy-doctor".to_string());

    match wintun::Adapter::open(&wintun, &adapter_name) {
        Ok(adapter) => {
            drop(adapter);
            TunProbe::pass(format!(
                "opened Wintun adapter '{}' ({})",
                adapter_name, source
            ))
        }
        Err(open_err) => match wintun::Adapter::create(&wintun, &adapter_name, "toppy", None) {
            Ok(adapter) => match delete_adapter(adapter) {
                Ok(true) => TunProbe::pass(format!(
                    "created and deleted Wintun adapter '{}' ({})",
                    adapter_name, source
                )),
                Ok(false) => TunProbe::warn(format!(
                    "created Wintun adapter '{}' ({}) but could not delete (handle shared)",
                    adapter_name, source
                )),
                Err(err) => TunProbe::warn(format!(
                    "created Wintun adapter '{}' ({}) but {}",
                    adapter_name, source, err
                )),
            },
            Err(create_err) => TunProbe::fail(format!(
                "failed to open or create Wintun adapter '{}': open={}, create={}",
                adapter_name, open_err, create_err
            )),
        },
    }
}
