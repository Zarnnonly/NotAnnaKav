#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod scanner;

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
async fn scan_folder(target: String, database: Option<String>) -> Result<scanner::Report, String> {
    tauri::async_runtime::spawn_blocking(move || scanner::scan(&target, database.as_deref()))
        .await
        .map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![choose_folder, scan_folder])
        .run(tauri::generate_context!())
        .expect("Failed to start NotAnnaKav");
}
