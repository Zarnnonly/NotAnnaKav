# AnnaKav

### A window appeared. Unfortunately, the work is still there.

I thought giving this thing a GUI would make it feel finished. A window, a few buttons, some numbers that go up. The usual ritual of convincing yourself that software is becoming software.

Anyway. AnnaKav now has a Tauri desktop interface.

What does it do? Walk through a folder, hash the files, compare those hashes against a local database, and tell you when something matches. Written like that, it sounds suspiciously simple. Then you have to deal with paths, unreadable files, binary records, and the small detail that the original program assumes everybody lives inside my Linux home directory.

They don't. Apparently.

## What is actually here

AnnaKav is an experimental, on-demand SHA-256 signature scanner. The original implementation is in C. The desktop app uses Tauri 2 with a Rust scanner and a plain HTML/CSS/JavaScript interface.

You select a target folder and a signature database. The scanner reads regular files recursively, computes their SHA-256 digest, and looks for an exact match. Findings include the file path, signature record name, and digest. You can export the report as JSON.

No cloud account. No upload step. File contents are processed locally.

The interface has a dark background because apparently I cannot inspect a file unless the application looks like it knows something I don't.

## Run it

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

1. Browse to the folder you want to inspect.
2. Select a signature database folder. The repository's `db/` folder contains legacy records you can load, but it is not a maintained threat intelligence feed.
3. Click **Start inspection**.
4. Review matches and warnings. Export the JSON report if you need the evidence outside the window.

The numbers appear when the scan finishes. There is no live file counter or cancellation button yet. Large folders can take time, and unreadable entries are counted as skipped. Symlinks are not followed.

A signature match means the file has the same SHA-256 digest as a record you supplied. How much that tells you depends on where the record came from. A filename in the database is a label, not a verdict handed down by some divine threat intelligence department.

## The database, because bytes have opinions

Each file in the database directory contains one signature. The desktop scanner accepts:

- **Legacy binary records:** exactly 32 bytes containing eight little-endian `uint32_t` SHA-256 words, compatible with the C writer on x86 systems. The extension does not matter; some existing `.txt` files are binary records.
- **Hex records:** one 64-character SHA-256 digest, with optional surrounding whitespace. Uppercase and lowercase are accepted.

Subdirectories are ignored. Invalid records produce warnings; an empty or entirely invalid database stops the scan. Duplicate hashes share one lookup entry and retain one label. Legacy records produced on a big-endian system need conversion first.

For a harmless end-to-end check, create a file containing exactly `abc` with no newline. Put the following digest in a separate database file:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Scan the folder containing `abc` using that database. A match verifies the workflow. It does not make `abc` malware. Please let those three letters live.

## The C code did not disappear

`annakav.c` and `headerUndUtil/` contain the original Linux CLI implementation: directory walking, executable filtering, hashing, signature lookup, permission checks, and checkpoint-related code.

The GUI does **not** execute that CLI. Its Rust backend implements the hashing and lookup workflow separately so it can work without the original hardcoded Linux paths or interactive terminal prompts. It scans all regular files, rather than relying on Unix executable permissions.

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
```

They cover legacy record decoding, hexadecimal record parsing, and a real folder scan against a known SHA-256 test vector.

## Next, probably

Live progress. Cancellation. Better signature metadata. A proper checkpoint strategy for the desktop scanner. More tests around filesystems that refuse to cooperate.

These are plans, not features hiding behind a button I forgot to explain.

Anyway. A window appeared. You can scan something now.

## License

See [LICENSE](LICENSE) for the repository's license terms.
