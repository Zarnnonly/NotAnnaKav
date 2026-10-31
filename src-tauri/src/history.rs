use crate::scanner::Report;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
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
    write_json(&destination, record)?;
    // The report is authoritative; a missing index entry is repaired by list().
    if let Ok(metadata) = fs::metadata(&destination) {
        let _ = cache_summary(root, Summary::from(record), &metadata);
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let temporary = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    let result = (|| {
        serde_json::to_writer(&mut writer, value)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e: std::io::Error| e.to_string())
}

pub fn read(root: &Path, id: &str) -> Result<Record, String> {
    #[cfg(test)]
    REPORT_READS.with(|reads| reads.set(reads.get() + 1));
    let file = fs::File::open(record_path(root, id)?).map_err(|e| e.to_string())?;
    let record: Record = serde_json::from_reader(BufReader::new(file))
        .map_err(|e| format!("Invalid saved report: {e}"))?;
    if record.id != id {
        return Err("Saved report identifier does not match its filename.".into());
    }
    Ok(record)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Summary {
    id: String,
    completed_at_ms: u64,
    target: String,
    scanned: u64,
    matches: usize,
    stopped: bool,
}

impl From<&Record> for Summary {
    fn from(record: &Record) -> Self {
        Self {
            id: record.id.clone(),
            completed_at_ms: record.completed_at_ms,
            target: record.target.clone(),
            scanned: record.report.scanned,
            matches: record.report.findings.len(),
            stopped: record.report.stopped,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct IndexEntry {
    version: u8,
    length: u64,
    modified_ns: Option<u128>,
    summary: Summary,
}

fn modified_ns(metadata: &fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
}

fn cache_summary(root: &Path, summary: Summary, metadata: &fs::Metadata) -> Result<(), String> {
    let index = root.join("index");
    fs::create_dir_all(&index).map_err(|e| e.to_string())?;
    let path = record_path(&index, &summary.id)?;
    write_json(
        &path,
        &IndexEntry {
            version: 1,
            length: metadata.len(),
            modified_ns: modified_ns(metadata),
            summary,
        },
    )
}

fn summary(root: &Path, id: &str) -> Result<Summary, String> {
    let metadata = fs::metadata(record_path(root, id)?).map_err(|e| e.to_string())?;
    if let Ok(file) = fs::File::open(record_path(&root.join("index"), id)?) {
        if let Ok(index) = serde_json::from_reader::<_, IndexEntry>(BufReader::new(file)) {
            if index.version == 1
                && index.summary.id == id
                && index.length == metadata.len()
                && index.modified_ns.is_some()
                && index.modified_ns == modified_ns(&metadata)
            {
                return Ok(index.summary);
            }
        }
    }
    let summary = Summary::from(&read(root, id)?);
    let _ = cache_summary(root, summary.clone(), &metadata);
    Ok(summary)
}

#[cfg(test)]
thread_local! { static REPORT_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

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
        match summary(root, id) {
            Ok(summary) => listing.entries.push(summary),
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
        REPORT_READS.with(|reads| reads.set(0));
        assert_eq!(list(&directory).unwrap().entries.len(), 1);
        REPORT_READS
            .with(|reads| assert_eq!(reads.get(), 0, "warm index must not read report payloads"));
        fs::remove_file(record_path(&directory.join("index"), &record.id).unwrap()).unwrap();
        assert_eq!(list(&directory).unwrap().entries.len(), 1);
        REPORT_READS.with(|reads| assert_eq!(reads.get(), 1, "legacy history is indexed once"));
        assert_eq!(list(&directory).unwrap().entries.len(), 1);
        REPORT_READS.with(|reads| assert_eq!(reads.get(), 1));
        fs::write(
            record_path(&directory.join("index"), &record.id).unwrap(),
            b"broken index",
        )
        .unwrap();
        assert_eq!(list(&directory).unwrap().entries.len(), 1);
        REPORT_READS.with(|reads| assert_eq!(reads.get(), 2, "corrupt index is repaired"));
        fs::write(directory.join("123.json"), b"broken").unwrap();
        let listing = list(&directory).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.warnings.len(), 1);
        assert!(read(&directory, "../sample").is_err());
        assert!(list(&root.join("missing")).unwrap().entries.is_empty());
        fs::write(
            record_path(&directory, &record.id).unwrap(),
            b"changed and corrupt",
        )
        .unwrap();
        let changed = list(&directory).unwrap();
        assert_eq!(
            changed.entries.len(),
            0,
            "changed reports must invalidate their cached summary"
        );
        assert_eq!(changed.warnings.len(), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
