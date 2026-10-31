use crate::scanner::Report;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub completed_at_ms: u64,
    pub target: String,
    pub database: String,
    #[serde(flatten)]
    pub report: Report,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_error: Option<String>,
}

impl Record {
    pub fn new(target: String, database: Option<String>, report: Report) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            id: format!("{}-{}", now.as_nanos(), std::process::id()),
            completed_at_ms: now.as_millis() as u64,
            target,
            database: database.unwrap_or_else(|| "bundled".into()),
            report,
            history_error: None,
        }
    }
}

fn record_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || id.len() > 80 || !id.bytes().all(|c| c.is_ascii_digit() || c == b'-') {
        return Err("Invalid history identifier.".into());
    }
    Ok(root.join(format!("{id}.json")))
}

pub fn save(root: &Path, record: &Record) -> Result<(), String> {
    let destination = record_path(root, &record.id)?;
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let temporary = destination.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(&serde_json::to_vec_pretty(record)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e: std::io::Error| e.to_string())
}

pub fn read(root: &Path, id: &str) -> Result<Record, String> {
    let bytes = fs::read(record_path(root, id)?).map_err(|e| e.to_string())?;
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid saved report: {e}"))?;
    if record.id != id {
        return Err("Saved report identifier does not match its filename.".into());
    }
    Ok(record)
}

#[derive(Serialize)]
pub struct Summary {
    id: String,
    completed_at_ms: u64,
    target: String,
    scanned: u64,
    matches: usize,
    stopped: bool,
}

#[derive(Serialize)]
pub struct Listing {
    pub entries: Vec<Summary>,
    pub warnings: Vec<String>,
}

pub fn list(root: &Path) -> Result<Listing, String> {
    let mut listing = Listing {
        entries: vec![],
        warnings: vec![],
    };
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(listing),
        Err(e) => return Err(e.to_string()),
    };
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        match read(root, id) {
            Ok(record) => listing.entries.push(Summary {
                id: record.id,
                completed_at_ms: record.completed_at_ms,
                target: record.target,
                scanned: record.report.scanned,
                matches: record.report.findings.len(),
                stopped: record.report.stopped,
            }),
            Err(e) => listing.warnings.push(format!("Could not load {id}: {e}")),
        }
    }
    listing.entries.sort_by(|a, b| {
        b.completed_at_ms
            .cmp(&a.completed_at_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
    listing.entries.truncate(100);
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    #[test]
    fn reports_survive_reload_and_corrupt_files_do_not_hide_valid_history() {
        let root = std::env::temp_dir().join(format!("notannakav-history-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let sample = root.join("sample.txt");
        fs::write(&sample, b"abc").unwrap();
        let report = crate::scanner::scan(
            sample.to_str().unwrap(),
            None,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(report.scanned, 1);
        let mut record = Record::new(sample.display().to_string(), None, report);
        record.report.stopped = true;
        let directory = root.join("history");
        save(&directory, &record).unwrap();
        let reloaded = read(&directory, &record.id).unwrap();
        assert_eq!(reloaded.target, record.target);
        assert!(reloaded.report.stopped);
        assert_eq!(reloaded.report.scanned, 1);
        fs::write(directory.join("123.json"), b"broken").unwrap();
        let listing = list(&directory).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.warnings.len(), 1);
        assert!(read(&directory, "../sample").is_err());
        assert!(list(&root.join("missing")).unwrap().entries.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
