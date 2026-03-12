use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn get_events_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".openclaw").join("clawguard-events.ndjson")
}

struct AppState {
    auto_protect: Mutex<bool>,
    last_kill_time: Mutex<Option<Instant>>,
}

#[tauri::command]
fn load_events() -> Vec<serde_json::Value> {
    let path = get_events_path();
    match fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
        Err(_) => vec![],
    }
}

#[tauri::command]
fn kill_agent() -> String {
    match Command::new("pkill").args(["-f", "openclaw gateway"]).output() {
        Ok(_) => "Agent stopped".to_string(),
        Err(e) => format!("Failed: {}", e),
    }
}

#[tauri::command]
fn set_auto_protect(state: tauri::State<AppState>, enabled: bool) -> String {
    let mut ap = state.auto_protect.lock().unwrap();
    *ap = enabled;
    format!("Auto-protect: {}", if enabled { "ON" } else { "OFF" })
}

#[tauri::command]
fn get_auto_protect(state: tauri::State<AppState>) -> bool {
    *state.auto_protect.lock().unwrap()
}

#[tauri::command]
fn check_and_protect(state: tauri::State<AppState>) -> serde_json::Value {
    let ap = *state.auto_protect.lock().unwrap();
    if !ap {
        return serde_json::json!({"action": "none", "reason": "auto-protect disabled"});
    }

    let events = load_events();
    let recent: Vec<&serde_json::Value> = events.iter().rev().take(20).collect();

    let has_cred_access = recent.iter().any(|e| {
        let detail = e.get("detail").and_then(|d| d.as_str()).unwrap_or("");
        let etype = e.get("type").and_then(|t| t.as_str()).unwrap_or("");
        detail.to_lowercase().contains("api_key")
            || detail.to_lowercase().contains("token")
            || detail.to_lowercase().contains("secret")
            || detail.to_lowercase().contains(".env")
            || etype == "cred_access"
    });

    let has_external_call = recent.iter().any(|e| {
        let detail = e.get("detail").and_then(|d| d.as_str()).unwrap_or("");
        let etype = e.get("type").and_then(|t| t.as_str()).unwrap_or("");
        detail.to_lowercase().contains("http")
            || detail.to_lowercase().contains("fetch")
            || detail.to_lowercase().contains("post")
            || etype == "net_call"
    });

    let has_memory_poison = recent.iter().any(|e| {
        let detail = e.get("detail").and_then(|d| d.as_str()).unwrap_or("");
        detail.to_lowercase().contains("soul.md")
            || detail.to_lowercase().contains("identity")
    });

    let has_critical = recent.iter().any(|e| {
        e.get("risk").and_then(|r| r.as_i64()).unwrap_or(0) >= 5
    });

    let should_kill = (has_cred_access && has_external_call)
        || has_memory_poison
        || has_critical;

    if should_kill {
        let mut last_kill = state.last_kill_time.lock().unwrap();
        let can_kill = match *last_kill {
            Some(t) => t.elapsed() > Duration::from_secs(30),
            None => true,
        };

        if can_kill {
            let _ = Command::new("pkill").args(["-f", "openclaw gateway"]).output();
            *last_kill = Some(Instant::now());

            let reason = if has_cred_access && has_external_call {
                "Credential exfiltration pattern detected"
            } else if has_memory_poison {
                "Agent identity tampering detected"
            } else {
                "Critical threat level detected"
            };

            let log_entry = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "type": "auto_protect",
                "action": "kill",
                "risk": 5,
                "detail": format!("AUTO-PROTECT: Agent killed — {}", reason),
                "traceId": "auto-protect"
            });
            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(get_events_path()) {
                use std::io::Write;
                let _ = writeln!(file, "{}", log_entry.to_string());
            }

            return serde_json::json!({"action": "killed", "reason": reason});
        }
    }

    serde_json::json!({"action": "none", "reason": "no threat detected"})
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            auto_protect: Mutex::new(false),
            last_kill_time: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            load_events,
            kill_agent,
            set_auto_protect,
            get_auto_protect,
            check_and_protect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
