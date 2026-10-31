use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use walkdir::WalkDir;

include!(concat!(env!("OUT_DIR"), "/bundled_signatures.rs"));

#[derive(Clone, Serialize)]
pub struct Finding {
    path: String,
    signature: String,
    sha256: String,
    size_bytes: u64,
    signature_source: String,
    detection_method: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
pub struct Report {
    scanned: u64,
    signatures: usize,
    skipped: u64,
    findings: Vec<Finding>,
    warnings: Vec<String>,
    stopped: bool,
    elapsed_ms: u64,
}

#[derive(Clone, Serialize, Default)]
pub struct Progress {
    phase: &'static str,
    scanned: u64,
    signatures: usize,
    skipped: u64,
    matches: usize,
    current_file: String,
    file_bytes: u64,
    file_size: u64,
    elapsed_ms: u64,
    finding: Option<Finding>,
}

struct Updates<F> {
    callback: F,
    started: Instant,
    last: Instant,
    progress: Progress,
}

impl<F: FnMut(Progress)> Updates<F> {
    fn send(&mut self, report: &Report, force: bool) {
        if !force && self.last.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.progress.scanned = report.scanned;
        self.progress.signatures = report.signatures;
        self.progress.skipped = report.skipped;
        self.progress.matches = report.findings.len();
        self.progress.elapsed_ms = self.started.elapsed().as_millis() as u64;
        (self.callback)(self.progress.clone());
        self.progress.finding = None;
        self.last = Instant::now();
    }
}

// The C database writer stores eight native u32 words, little-endian on x86.
fn decode_signature(bytes: &[u8]) -> Option<String> {
    if bytes.len() == 32 {
        return Some(
            bytes
                .chunks_exact(4)
                .map(|b| format!("{:08x}", u32::from_le_bytes(b.try_into().unwrap())))
                .collect(),
        );
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    (text.len() == 64 && text.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| text.to_ascii_lowercase())
}

fn hash_file(
    path: &Path,
    cancel: &AtomicBool,
    mut update: impl FnMut(u64, u64),
) -> io::Result<Option<(String, u64)>> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut read = 0;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        read += count as u64;
        update(read, size);
    }
    Ok(Some((format!("{:x}", hasher.finalize()), read)))
}

pub fn scan(
    target: &str,
    database: Option<&str>,
    cancel: &AtomicBool,
    on_progress: impl FnMut(Progress),
) -> Result<Report, String> {
    let started = Instant::now();
    let mut updates = Updates {
        callback: on_progress,
        started,
        last: started,
        progress: Progress {
            phase: "loading",
            ..Progress::default()
        },
    };
    let mut signatures = HashMap::new();
    let mut report = Report {
        scanned: 0,
        signatures: 0,
        skipped: 0,
        findings: vec![],
        warnings: vec![],
        stopped: false,
        elapsed_ms: 0,
    };
    updates.send(&report, true);
    if target.trim().is_empty() {
        return Err("Select a target folder.".into());
    }
    let target = fs::canonicalize(target).map_err(|e| format!("Target: {e}"))?;
    if !target.is_dir() {
        return Err("Target must be a directory.".into());
    }
    let mut source = String::from("Included database");
    if let Some(database) = database {
        if database.trim().is_empty() {
            return Err(
                "Select a custom database folder or switch to the included database.".into(),
            );
        }
        let database = fs::canonicalize(database).map_err(|e| format!("Database: {e}"))?;
        source = database.display().to_string();
        for entry in fs::read_dir(&database).map_err(|e| format!("Database: {e}"))? {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            updates.send(&report, false);
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
                continue;
            }
            // Read at most 4 KiB: a signature is 32 binary bytes or 64 hex characters.
            let bytes = File::open(entry.path())
                .and_then(|f| {
                    let mut bytes = vec![];
                    f.take(4096).read_to_end(&mut bytes)?;
                    Ok(bytes)
                })
                .map_err(|e| format!("Cannot read signature {}: {e}", entry.path().display()))?;
            match decode_signature(&bytes) {
                Some(hash) => {
                    signatures
                        .entry(hash)
                        .or_insert_with(|| entry.file_name().to_string_lossy().into_owned());
                }
                None => report
                    .warnings
                    .push(format!("Invalid signature: {}", entry.path().display())),
            }
        }
    } else {
        for (name, bytes) in BUNDLED_SIGNATURES {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            match decode_signature(bytes) {
                Some(hash) => {
                    signatures.entry(hash).or_insert_with(|| (*name).to_owned());
                }
                None => report
                    .warnings
                    .push(format!("Invalid bundled signature: {name}")),
            }
        }
    }
    if signatures.is_empty() && !cancel.load(Ordering::Relaxed) {
        return Err("No valid SHA-256 signatures found in the database.".into());
    }
    report.signatures = signatures.len();
    updates.progress.phase = "scanning";
    updates.send(&report, true);
    for entry in WalkDir::new(&target).follow_links(false) {
        if cancel.load(Ordering::Relaxed) {
            report.stopped = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                report.skipped += 1;
                if report.warnings.len() < 200 {
                    report.warnings.push(e.to_string());
                }
                updates.send(&report, false);
                continue;
            }
        };
        if !entry.file_type().is_file() {
            updates.send(&report, false);
            continue;
        }
        updates.progress.current_file = entry.path().display().to_string();
        updates.progress.file_bytes = 0;
        updates.progress.file_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        updates.send(&report, false);
        match hash_file(entry.path(), cancel, |bytes, size| {
            updates.progress.file_bytes = bytes;
            updates.progress.file_size = size;
            updates.send(&report, false);
        }) {
            Ok(Some((hash, size))) => {
                report.scanned += 1;
                if let Some(signature) = signatures.get(&hash) {
                    let finding = Finding {
                        path: entry.path().display().to_string(),
                        signature: signature.clone(),
                        sha256: hash,
                        size_bytes: size,
                        signature_source: source.clone(),
                        detection_method: "Exact SHA-256 match",
                        reason: "The file digest exactly matches a supplied signature. The signature label is not an independently verified malware verdict.",
                    };
                    report.findings.push(finding.clone());
                    updates.progress.finding = Some(finding);
                    updates.send(&report, true);
                }
            }
            Ok(None) => {
                report.stopped = true;
                break;
            }
            Err(e) => {
                report.skipped += 1;
                if report.warnings.len() < 200 {
                    report
                        .warnings
                        .push(format!("{}: {e}", entry.path().display()));
                }
            }
        }
        updates.send(&report, false);
    }
    report.stopped |= cancel.load(Ordering::Relaxed);
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    updates.progress.phase = if report.stopped {
        "stopped"
    } else {
        "complete"
    };
    updates.send(&report, true);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scan(target: &str, database: Option<&str>) -> Result<Report, String> {
        super::scan(target, database, &AtomicBool::new(false), |_| {})
    }
    #[test]
    fn reads_legacy_words_and_hex() {
        let bytes: Vec<u8> = (0u32..8).flat_map(u32::to_le_bytes).collect();
        let expected: String = (0u32..8).map(|n| format!("{n:08x}")).collect();
        assert_eq!(decode_signature(&bytes), Some(expected.clone()));
        assert_eq!(
            decode_signature(format!("{}\n", expected.to_uppercase()).as_bytes()),
            Some(expected)
        );
        assert_eq!(decode_signature(b"invalid"), None);
    }
    #[test]
    fn scans_real_files_and_matches_sha256() {
        let root = std::env::temp_dir().join(format!("annakav-test-{}", std::process::id()));
        let target = root.join("target");
        let db = root.join("db");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&db).unwrap();
        fs::write(target.join("sample.txt"), b"abc").unwrap();
        fs::write(
            db.join("test.sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        let report = scan(target.to_str().unwrap(), Some(db.to_str().unwrap())).unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.skipped, 0);
        assert!(!report.stopped);
        assert_eq!(report.findings[0].size_bytes, 3);
        assert_eq!(report.findings[0].detection_method, "Exact SHA-256 match");
        assert!(report.findings[0].signature_source.contains("db"));
        let cancel = AtomicBool::new(false);
        let mut updates = vec![];
        let partial = super::scan(
            target.to_str().unwrap(),
            Some(db.to_str().unwrap()),
            &cancel,
            |p| {
                if p.matches == 1 {
                    cancel.store(true, Ordering::Relaxed);
                }
                updates.push(p);
            },
        )
        .unwrap();
        assert!(partial.stopped);
        assert_eq!(partial.findings.len(), 1);
        assert!(updates.iter().any(|p| p.finding.is_some()));
        assert_eq!(updates.last().unwrap().phase, "stopped");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundled_database_works_without_a_database_path() {
        assert!(!BUNDLED_SIGNATURES.is_empty());
        assert!(BUNDLED_SIGNATURES
            .iter()
            .all(|(_, bytes)| decode_signature(bytes).is_some()));
        let target =
            std::env::temp_dir().join(format!("notannakav-bundled-{}", std::process::id()));
        fs::create_dir_all(&target).unwrap();
        let report = scan(target.to_str().unwrap(), None).unwrap();
        assert!(report.signatures > 0);
        assert_eq!(report.scanned, 0);
        assert!(report.warnings.is_empty());
        assert!(scan(target.to_str().unwrap(), Some("")).is_err());
        assert!(scan(
            target.to_str().unwrap(),
            Some("nonexistent-database-folder")
        )
        .is_err());
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn cancellation_during_hash_does_not_return_a_partial_digest() {
        let path = std::env::temp_dir().join(format!("notannakav-chunks-{}", std::process::id()));
        fs::write(&path, vec![42u8; 200_000]).unwrap();
        let cancel = AtomicBool::new(false);
        let mut observed = 0;
        let hash = hash_file(&path, &cancel, |bytes, _| {
            observed = bytes;
            cancel.store(true, Ordering::Relaxed);
        })
        .unwrap();
        assert!(hash.is_none());
        assert_eq!(observed, 65536);
        fs::remove_file(path).unwrap();
    }
}
