# NotAnnaKav

**Current source version: v1.2.0** — Windows desktop plus Linux pure C CLI and Tauri desktop. See the [release notes](docs/releases/v1.2.0.md). Packaged Linux downloads are produced by CI after a successful build.

### A window appeared. Unfortunately, the work is still there.

I thought giving this thing a GUI would make it feel finished. A window, a few buttons, some numbers that go up. The usual ritual of convincing yourself that software is becoming software.

Anyway. NotAnnaKav now has a Tauri desktop interface.

What does it do? Walk through a folder, hash the files, compare those hashes against a local database, and tell you when something matches. Written like that, it sounds suspiciously simple. Then you have to deal with paths, unreadable files, binary records, and the small detail that the original program assumes everybody lives inside my Linux home directory.

They don't. Apparently.

## What is actually here

NotAnnaKav is an experimental, on-demand SHA-256 signature scanner. The original implementation is in C. The desktop app uses Tauri 2 with a Rust scanner and a plain HTML/CSS/JavaScript interface.

You select a file or folder. The included signature database is used automatically. The scanner reads the selected file, or regular files recursively within a folder, computes their SHA-256 digest, and looks for an exact match. Findings include the file path, size, signature record, database source, digest, and an explanation of the match. You can export the report as JSON.

No cloud account. No upload step. File contents are processed locally.

The interface has a dark background because apparently I cannot inspect a file unless the application looks like it knows something I don't.

## Run it

Linux has two versions: a **pure C CLI** (`make`, then
`./build/annakav-cli TARGET ./db`) and a **Tauri desktop with C hashing**.
For both versions backed by the original AnnaKav C SHA-256 code,
see [Linux build and architecture](docs/LINUX.md). Linux builds use the C
compression function through FFI; Windows retains the Rust implementation.

You need Node.js with npm, a stable Rust toolchain, and the native development requirements for Tauri. On Windows, that includes Microsoft C++ Build Tools with the desktop C++ workload, the Windows SDK, and WebView2. Other platforms need their corresponding system libraries; see the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

From the repository root:

```sh
npm install
npm run dev
```

The first build downloads and compiles the Rust dependencies. It may take a while. This is the part where you stare at the terminal and reconsider what you meant by a small GUI.

For a release build:

```sh
npm run build
```

Build output goes under `src-tauri/target/release/`; installers, when generated, go under its `bundle/` directory. Packaging and signing requirements depend on the operating system.

## Actually scan something

1. Use **Choose file** or **Browse folder**, or drop one file or folder anywhere in the application window. Dropping selects the target; it does not start a scan automatically. Multiple dropped items are rejected so nothing is silently omitted.
2. Leave the included database selected. No database download or folder selection is required. To use your own records, open **Advanced settings**, enable **Use my own signature database**, and choose its folder.
3. Click **Start inspection**.
4. Review matches and warnings. Export the JSON report if you need the evidence outside the window.

The numbers update while the scan runs: files hashed, signature matches, loaded signatures, and skipped entries. The progress panel shows the current file, bytes read, and elapsed time. Files are discovered as the scanner walks, so there is no invented overall percentage. Large folders can take time, and unreadable entries are counted as skipped. Symlinks are not followed.

Click **Stop** to request cancellation. The scanner checks between entries and between 64 KiB reads; a filesystem operation already waiting on the operating system must return first. Completed findings are retained, and the result is explicitly marked as partial. You can still export it; JSON reports include `stopped` and `elapsed_ms`. A partially hashed file is never compared as if its digest were complete.

Matches appear during the scan. Open **View finding details** to inspect the path, size, SHA-256, signature record and database source, detection method, and reason. A match is reported only: the file is not deleted, changed, or quarantined.

Findings are displayed 50 at a time; use **Previous** and **Next** to navigate. Details are loaded into the view when expanded. JSON export includes every finding, regardless of the page you are viewing.

## And now it has network visibility

Network Monitor is included in v1.1.0 and later Windows builds.

Open **Network Monitor** in the sidebar on Windows to inspect TCP IPv4/IPv6 connections and listening ports. Entries include the owning PID, process name, local and remote endpoints, TCP state, and executable path where accessible. Listener bindings distinguish localhost, all interfaces, and a specific interface; a binding does not establish reachability through a firewall or router.

Snapshots refresh about two seconds after the previous request completes, only while this view is open. Use **Pause**, **Refresh now**, process/IP/path filtering, and the connections/listeners selector. Results are paginated at 50 entries. The monitor reads Windows TCP tables without a packet capture driver; it does not capture traffic contents, record network history, count bandwidth, or block connections. Brief connections between snapshots can be missed. UDP is not included.

Open **Process details** for the executable path. **Scan executable** switches to Threat scanner and starts a file inspection using the currently selected signature database. Protected or exited processes may have no accessible path; their scan button is disabled. Finish or stop an existing file inspection before starting another. Snapshot ownership is time-sensitive: a process can exit, a PID can be reused, and a file can change before inspection. A connection, port, or process name alone is not a malware verdict.

## It remembers now

Completed and stopped scans are saved automatically. Scroll to **Scan history**, then click **Open report** to review a previous result and export its JSON. The saved report's target, date, database, and completion status appear above its findings. Opening history does not run another scan.

History survives application restarts. Reports live under the operating system's local application data directory, in `io.notannakav.desktop/scan-history` (on Windows, typically `%LOCALAPPDATA%\io.notannakav.desktop\scan-history`). The interface shows the newest 100 records; older files remain on disk. Reports include local paths and signature evidence, not copies of scanned files. There is no automatic deletion policy yet.

A stopped scan is saved as partial. A scan that fails before returning a report is not saved. If saving fails, the scan result stays visible and exportable, with an error explaining that history was not saved. Unreadable history files are reported without hiding valid records.

History uses a small summary index so refreshing the list does not repeatedly load every report's findings. Old reports are indexed automatically the first time they are listed. The list refreshes in the background after a scan, so you can start another inspection immediately after its result appears.

A signature match means the file has the same SHA-256 digest as a record you supplied. How much that tells you depends on where the record came from. A filename in the database is a label, not a verdict handed down by some divine threat intelligence department.

## The database, because bytes have opinions

The repository's `db/` records are embedded in the desktop executable during the build. They work in development and installed builds, even when the repository is not present. Updating `db/` requires rebuilding the app. These are starter legacy records, not a maintained threat intelligence feed, and there are no automatic updates.

A custom database replaces the included records for that scan. Invalid or missing custom folders produce an error instead of silently switching databases. Exported reports identify the database as `bundled` or record the selected custom path.

Each file in the database directory contains one signature. The desktop scanner accepts:

- **Legacy binary records:** exactly 32 bytes containing eight little-endian `uint32_t` SHA-256 words, compatible with the C writer on x86 systems. The extension does not matter; some existing `.txt` files are binary records.
- **Hex records:** one 64-character SHA-256 digest, with optional surrounding whitespace. Uppercase and lowercase are accepted.

Subdirectories are ignored. Invalid records produce warnings; an empty or entirely invalid database stops the scan. Duplicate hashes share one lookup entry and retain one label. Legacy records produced on a big-endian system need conversion first.

For a harmless end-to-end check, create a file containing exactly `abc` with no newline. Put the following digest in a separate database file:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

In **Advanced settings**, select that separate folder as your custom database, then scan the folder containing `abc`. A match verifies the workflow. It does not make `abc` malware. Please let those three letters live.

## The C code did not disappear

`annakav.c` and `headerUndUtil/` contain the original Linux CLI implementation: directory walking, executable filtering, hashing, signature lookup, permission checks, and checkpoint-related code.

The GUI does **not** execute that CLI. On Linux it links the original C SHA-256 compression function through FFI, with corrected padding in a streaming adapter. Rust manages traversal, reads, signature lookup and reports; Windows also uses Rust for hashing. It scans all regular files, rather than relying on Unix executable permissions, without the original hardcoded paths or terminal prompts.

The original permission-changing routine and checkpoint code are not connected to the desktop app. The GUI does not change system permissions, delete files, or quarantine anything.

If you are here to study the original implementation, it is still here. If you are here to use the desktop app, start with `src-tauri/` and `ui/`.

## What this cannot promise

No match does not mean safe. It means no supplied signature matched the files successfully hashed.

Change a file's contents and its hash changes. Unknown malware, modified samples, packed content, and files inside archives will not magically reveal themselves. There is no behavioral analysis, real-time protection, automatic signature update service, archive extraction, remediation, or independent detection benchmark here.

Files can also change while being scanned. This is a read-only inspection tool, not a forensic snapshot mechanism. Run it with ordinary user permissions and review coverage warnings before drawing conclusions.

So yes, this is a cybersecurity project. No, I am not going to call a hash lookup engine an autonomous defense platform. I still have to finish the ordinary parts.

## Project map

```text
ui/                    Desktop interface
src-tauri/src/         Tauri commands and Rust scanner
src-tauri/             Desktop configuration and Cargo manifest
db/                    Existing legacy signature records
annakav.c              Original C entry point
headerUndUtil/         Original hashing, walking, lookup, checkpoint code
Etherane/Anna/         Development notes
docs/ARCHITECTURE.md   Desktop design and security boundaries
docs/PITCH.md          Short project introduction
```

Run the scanner tests with:

```sh
npm test
npm run test:ui
```

They cover legacy record decoding, hexadecimal record parsing, embedded database loading, known SHA-256 matches, cancellation during hashing, partial results, and scan lifecycle protection. UI logic tests check database selection, live progress, finding details, Stop requests, and failure handling through a simulated Tauri bridge.

## Next, probably

Better signature metadata. History retention controls. A proper checkpoint strategy for the desktop scanner. More tests around filesystems that refuse to cooperate.

These are plans, not features hiding behind a button I forgot to explain.

Anyway. A window appeared. You can scan something now.

## License

Licensed under the [MIT License](LICENSE).
