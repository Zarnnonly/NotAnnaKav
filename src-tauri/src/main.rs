#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod history;
mod scanner;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{ipc::Channel, Manager, State};

fn history_directory(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|p| p.join("scan-history"))
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_history(app: tauri::AppHandle) -> Result<history::Listing, String> {
    let root = history_directory(&app)?;
    tauri::async_runtime::spawn_blocking(move || history::list(&root))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn read_history(app: tauri::AppHandle, id: String) -> Result<history::Record, String> {
    let root = history_directory(&app)?;
    tauri::async_runtime::spawn_blocking(move || history::read(&root, &id))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn choose_file() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .pick_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .ok()
    .flatten()
}

#[derive(Default, Clone)]
struct ScanState(Arc<Mutex<Option<(String, Arc<AtomicBool>)>>>);

impl ScanState {
    fn begin(&self, id: String) -> Result<Arc<AtomicBool>, String> {
        let mut active = self.0.lock().map_err(|e| e.to_string())?;
        if active.is_some() {
            return Err("An inspection is already running.".into());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        *active = Some((id, cancel.clone()));
        Ok(cancel)
    }

    fn stop(&self, id: &str) -> Result<bool, String> {
        let active = self.0.lock().map_err(|e| e.to_string())?;
        if let Some((active_id, cancel)) = active.as_ref() {
            if active_id == id {
                cancel.store(true, Ordering::Relaxed);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct ScanGuard(ScanState);
impl Drop for ScanGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0 .0.lock() {
            *active = None;
        }
    }
}

#[tauri::command]
fn stop_scan(scan_id: String, state: State<'_, ScanState>) -> Result<bool, String> {
    state.stop(&scan_id)
}

#[tauri::command]
async fn choose_folder() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .pick_folder()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
async fn scan_folder(
    target: String,
    database: Option<String>,
    scan_id: String,
    on_progress: Channel<scanner::Progress>,
    state: State<'_, ScanState>,
    app: tauri::AppHandle,
) -> Result<history::Record, String> {
    let cancel = state.begin(scan_id)?;
    let state = state.inner().clone();
    let history_root = history_directory(&app);
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = ScanGuard(state);
        let report = scanner::scan(&target, database.as_deref(), &cancel, |progress| {
            // A closed window should not leave an unattended inspection running.
            if on_progress.send(progress).is_err() {
                cancel.store(true, Ordering::Relaxed);
            }
        })?;
        let mut record = history::Record::new(target, database, report);
        if let Err(error) = history_root.and_then(|root| history::save(&root, &record)) {
            record.history_error = Some(format!("Could not save scan history: {error}"));
        }
        Ok(record)
    })
    .await
    .map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .manage(ScanState::default())
        .invoke_handler(tauri::generate_handler![
            choose_folder,
            choose_file,
            list_history,
            read_history,
            scan_folder,
            stop_scan
        ])
        .run(tauri::generate_context!())
        .expect("Failed to start NotAnnaKav");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_scan_at_a_time_and_stale_stop_cannot_cancel_next_scan() {
        let state = ScanState::default();
        let first = state.begin("first".into()).unwrap();
        assert!(state.begin("second".into()).is_err());
        assert!(!state.stop("old").unwrap());
        assert!(!first.load(Ordering::Relaxed));
        assert!(state.stop("first").unwrap());
        assert!(first.load(Ordering::Relaxed));
        drop(ScanGuard(state.clone()));
        let second = state.begin("second".into()).unwrap();
        assert!(!state.stop("first").unwrap());
        assert!(!second.load(Ordering::Relaxed));
        drop(ScanGuard(state));
    }
}
