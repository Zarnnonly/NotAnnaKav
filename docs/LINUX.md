# Two Linux versions

## Pure C CLI

Needs a Linux C compiler and Make; no Node.js, Rust or WebKit dependency.
From the repository root:

```sh
make
./build/annakav-cli /path/to/target ./db
make test # optional integration tests, requires Python 3
```

The target may be a regular file or directory. The database argument is required
and accepts the same little-endian legacy records and hex records as the desktop.
All regular files are inspected recursively, symlinks are skipped. Matches print
the path, signature label and SHA-256. Ctrl+C stops the scan. Exit codes: 0 means
no matches, 1 matches, 2 error/incomplete coverage, 130 interrupted. No match is
not a guarantee of safety. No files or permissions are modified.

`linux/cli.c` uses the original `MultiSha` function with corrected padding and
new traversal/database loading, without the old hardcoded paths. The legacy
`annakav.c` remains available for reference. CLI output is plain text; GUI history,
JSON export and network monitoring are not part of this version. CI uploads the
CLI and database separately as `NotAnnaKav-linux-pure-c`.

## Tauri desktop + C hashing

Linux builds link `headerUndUtil/sha.c` directly into the Tauri application.
The adapter calls the original `MultiSha` compression function for every block.
It supplies standard SHA-256 padding because the legacy file helpers mishandle
empty files and several block boundaries. No CLI subprocess or hardcoded home
directory is needed. Rust owns file reads, cancellation, traversal, signature
lookup, reports and history; C performs SHA-256 compression. Windows keeps its
existing Rust hash implementation. This is not a port of the entire C CLI.

On Ubuntu 22.04 or newer, install Node.js/npm and stable Rust, then:

```sh
sudo apt update
sudo apt install build-essential libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf
npm ci
npm run dev
npm test
npm run test:ui
npm run build -- --bundles deb,appimage
```

See the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for
other distributions. Build natively on Linux. Packages appear under
`src-tauri/target/release/bundle/`. The Linux GitHub Actions workflow tests
the C adapter against Rust SHA-256 at padding/read boundaries and uploads
DEB and AppImage artifacts. A workflow being present does not mean it has run.

The application runs as an ordinary user. Scan, Stop, custom databases,
history and export use the existing interface. Network Monitor remains
Windows-only. The CLI permission-changing/checkpoint routines are not invoked.
