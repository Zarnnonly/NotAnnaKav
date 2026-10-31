# Desktop architecture

NotAnnaKav Desktop separates presentation from local file inspection. The existing C CLI remains an independent implementation.

## Execution flow

1. The local HTML interface invokes `choose_folder` or `choose_file` for native selection, accepts a manually entered path, or uses Tauri's native webview drag-and-drop events. A drop selects exactly one file or directory without automatically starting inspection. Active inspections reject target changes. The included database is selected by default.
2. `scan_folder` receives the target and an optional custom database path through Tauri IPC. An omitted or null database uses the embedded records. An explicitly empty custom path is an error.
3. The command runs the scanner on a blocking worker so filesystem work does not block the UI thread.
4. The scanner canonicalizes the target and any custom database path, loads signatures into a hash map, walks either the single file or target directory, and hashes regular files in 64 KiB chunks.
5. A Tauri channel streams progress and matches to the interface. The final report includes input paths, completion time, counts, findings, warnings, `stopped`, and `elapsed_ms` in JSON exports.

The database is loaded once per scan. Lookup uses a hash map keyed by the 32-byte SHA-256 digest. Hexadecimal strings are created only for matched files. File size is obtained from the opened file handle, without a separate metadata query before hashing. Traversal does not follow symbolic links. Hashing is sequential; the working buffer does not grow with file size. Findings are retained in memory, so report size grows with the number of matches.

Routine progress messages are sent after 100 ms or when 128 new findings accumulate. Messages contain at most 128 findings and their starting offset. Phase transitions force delivery; completion and cancellation flush remaining findings. Progress includes counts, current path, file bytes read, file size, and elapsed milliseconds. There is no pre-count pass or overall percentage. The frontend displays 50 finding cards per page, creates details only when expanded, and reuses the visible live cards on completion. Export still includes the entire report.

The backend permits one active inspection. `stop_scan` accepts its scan ID and sets an atomic cancellation flag. Stale requests cannot cancel another inspection. A worker guard releases the active slot on completion or failure. Cancellation is checked during database loading, traversal, and before each file read. Already-blocked OS calls cannot be interrupted. Interrupted hashes are discarded; completed findings remain available in a report marked `stopped: true`. A channel send failure also requests cancellation. Late progress messages are ignored after frontend completion.

Each finding records the path, bytes hashed, exact SHA-256, record label, database source, detection method, and an explanation. The source identifies the included database or canonical custom directory; it does not establish threat intelligence provenance or independently verify the label.

`build.rs` embeds regular files from the repository's `db/` directory into generated Rust data. Cargo tracks that directory and its records to rebuild on changes. The executable needs no database extraction, resource path lookup, working-directory convention, or network connection. A custom database replaces the embedded set; load errors never trigger an implicit fallback. Reports exported by the interface identify the source as `bundled` or the supplied custom path. The included legacy records have no automatic update or provenance verification service.

## Data compatibility

Legacy signature files contain eight little-endian 32-bit words. Each word is decoded and converted to its big-endian bytes to reconstruct the SHA-256 digest. This is deliberately different from interpreting the stored bytes directly as a SHA-256 byte string. Hexadecimal database records are decoded into the same 32-byte representation.

Alternatively, a signature file can contain one ASCII hexadecimal digest. Invalid records are reported, and zero usable signatures is an error. Multiple labels for the same digest collapse to one lookup entry.

## Security boundaries

- Frontend assets are local. The content security policy restricts scripts and styles to the application origin and allows Tauri IPC connections.
- Native file/folder selection, scanning, cancellation, and history listing/reading are exposed through specific Rust commands. The app does not expose shell execution to the frontend.
- Inspection uses the operating system permissions of the current process. It does not request elevation or bypass access controls.
- File paths, labels, and errors are rendered as text, avoiding HTML interpretation of filesystem-controlled values.
- Scanning does not intentionally modify inspected files. It does not invoke the C permission repair routine.
- JSON reports can contain sensitive local paths. The user controls where exported reports are shared.

Custom Rust commands can access paths accepted by the scanner; the window capability is not a filesystem sandbox for those commands. Native dialogs improve selection usability, while the Rust backend validates that the target is a regular file or directory and reads any explicitly supplied custom database directory.

## Persistent history

After successful completion or cooperative cancellation, the backend saves the report under `app_local_data_dir()/scan-history`. Each record contains a backend-generated identifier, completion timestamp, requested target, database source, and the full report. JSON serialization streams through a 64 KiB buffered writer to a unique temporary file, which is flushed, synced, and renamed to the final JSON filename. This avoids allocating a complete serialized copy of the report. History writes run on the blocking worker. Save failures are returned alongside the report instead of discarding the inspection result.

`list_history` returns summaries for the newest 100 records. A per-record index under `scan-history/index` stores each small summary along with a schema version, report length, and modification timestamp. Listing still enumerates report filenames and checks metadata, but valid index entries avoid reading and deserializing full reports. Missing, stale, or corrupt entries are regenerated from the authoritative report. Existing history is migrated lazily on its first listing; a failed cache write does not discard a saved report. This cache is an optimization, not a tamper-detection mechanism.

`read_history` reads and validates one complete report through a buffered reader; identifiers are restricted to digits and hyphens, and the record ID must match the filename. No caller-supplied filesystem path is accepted by history commands. The frontend loads history on startup and refreshes it in the background after scans, without keeping scan controls disabled. A saved report can be opened and exported while idle; late read responses cannot replace a newly started scan. History files remain until manually removed; this version has no retention or deletion UI. Failed scans that do not return a report are not recorded.

## Network Monitor (Windows)

`network_snapshot` reads IPv4 and IPv6 owner-PID TCP tables through `GetExtendedTcpTable` on a blocking worker. Buffers are aligned and bounded, retry on table growth, and validate row bounds before decoding SDK structs. Per-snapshot process metadata is cached by PID. Executable paths are queried using limited process access, and every successful process handle is closed. System entries and inaccessible/exited processes remain visible with unavailable-path notes. If one address family fails, the snapshot includes the other and a warning; if both fail, the command returns an error. Other operating systems return an explicit unsupported error.

The sidebar view polls about two seconds after each response. Requests do not overlap; leaving the view cancels pending timers and invalidates in-flight responses. Pause stops automatic polling while preserving manual refresh. Failure retains the previous snapshot with a stale-data message. Filters run locally; only 50 rows are rendered per page. No packet content, UDP table, network history, threat classification, or firewall action is implemented. The executable scan action reuses the existing file scanner and current database. Connections and process paths are snapshots, not atomic proof of ownership at scan time.

## Operational limits

There is no checkpoint persistence, concurrent scan queue, real-time watcher, or file snapshot isolation. Stopped scans cannot resume from their previous position. Warning retention is capped at 200 during traversal; invalid database record warnings are retained separately in the same report. Skipped counts can include directory traversal errors and do not represent an exact number of unreadable files.

The scanner does not authenticate database provenance, unpack archives, classify unknown binaries, or validate whether a signature label correctly identifies malware. Platform-specific packaging and native dialog behavior require validation on each release target.
