use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read},
    path::Path,
};
use walkdir::WalkDir;

include!(concat!(env!("OUT_DIR"), "/bundled_signatures.rs"));

#[derive(Serialize)]
pub struct Finding {
    path: String,
    signature: String,
    sha256: String,
}

#[derive(Serialize)]
pub struct Report {
    scanned: u64,
    signatures: usize,
    skipped: u64,
    findings: Vec<Finding>,
    warnings: Vec<String>,
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

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn scan(target: &str, database: Option<&str>) -> Result<Report, String> {
    if target.trim().is_empty() {
        return Err("Select a target folder.".into());
    }
    let target = fs::canonicalize(target).map_err(|e| format!("Target: {e}"))?;
    if !target.is_dir() {
        return Err("Target must be a directory.".into());
    }
    let mut signatures = HashMap::new();
    let mut report = Report {
        scanned: 0,
        signatures: 0,
        skipped: 0,
        findings: vec![],
        warnings: vec![],
    };
    if let Some(database) = database {
        if database.trim().is_empty() {
            return Err(
                "Select a custom database folder or switch to the included database.".into(),
            );
        }
        let database = fs::canonicalize(database).map_err(|e| format!("Database: {e}"))?;
        for entry in fs::read_dir(&database).map_err(|e| format!("Database: {e}"))? {
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
    if signatures.is_empty() {
        return Err("No valid SHA-256 signatures found in the database.".into());
    }
    report.signatures = signatures.len();
    for entry in WalkDir::new(&target).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                report.skipped += 1;
                if report.warnings.len() < 200 {
                    report.warnings.push(e.to_string());
                }
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        match hash_file(entry.path()) {
            Ok(hash) => {
                report.scanned += 1;
                if let Some(signature) = signatures.get(&hash) {
                    report.findings.push(Finding {
                        path: entry.path().display().to_string(),
                        signature: signature.clone(),
                        sha256: hash,
                    });
                }
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
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
