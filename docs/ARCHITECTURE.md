# Desktop architecture

NotAnnaKav Desktop separates presentation from local file inspection. The existing C CLI remains an independent implementation.

## Execution flow

1. The local HTML interface invokes `choose_folder` to open a native directory picker, or accepts a manually entered path.
2. `scan_folder` receives the target and database paths through Tauri IPC.
3. The command runs the scanner on a blocking worker so filesystem work does not block the UI thread.
4. The scanner canonicalizes paths, loads signatures into a hash map, traverses the target, and hashes regular files in 64 KiB chunks.
5. The complete report returns to the interface. JSON export includes input paths, completion time, counts, findings, and warnings.

The database is loaded once per scan. Lookup uses a hash map keyed by the normalized hexadecimal digest. Traversal does not follow symbolic links. Hashing is sequential; the working buffer does not grow with file size. Findings are retained in memory, so report size grows with the number of matches. The UI receives results only at completion.

## Data compatibility

Legacy signature files contain eight little-endian 32-bit words. Each word is formatted as eight hexadecimal digits to reconstruct the digest. This is deliberately different from interpreting the stored bytes directly as a SHA-256 byte string.

Alternatively, a signature file can contain one ASCII hexadecimal digest. Invalid records are reported, and zero usable signatures is an error. Multiple labels for the same digest collapse to one lookup entry.

## Security boundaries

- Frontend assets are local. The content security policy restricts scripts and styles to the application origin and allows Tauri IPC connections.
- Filesystem operations are exposed through two specific Rust commands. The app does not expose shell execution to the frontend.
- Inspection uses the operating system permissions of the current process. It does not request elevation or bypass access controls.
- File paths, labels, and errors are rendered as text, avoiding HTML interpretation of filesystem-controlled values.
- Scanning does not intentionally modify inspected files. It does not invoke the C permission repair routine.
- JSON reports can contain sensitive local paths. The user controls where exported reports are shared.

Custom Rust commands can access paths accepted by the scanner; the window capability is not a filesystem sandbox for those commands. Native dialogs improve selection usability, while the Rust backend validates that both supplied paths resolve to directories.

## Operational limits

There is no cancellation, checkpoint persistence, concurrent scan queue, real-time watcher, or file snapshot isolation. An in-flight scan continues until traversal completes or the process exits. Warning retention is capped at 200 during traversal; invalid database record warnings are retained separately in the same report. Skipped counts can include directory traversal errors and do not represent an exact number of unreadable files.

The scanner does not authenticate database provenance, unpack archives, classify unknown binaries, or validate whether a signature label correctly identifies malware. Platform-specific packaging and native dialog behavior require validation on each release target.
