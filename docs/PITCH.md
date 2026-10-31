# AnnaKav — inspect what you can verify

Security tools can make very large promises. AnnaKav starts with a smaller question: does this file match a signature I already know?

It is an experimental desktop scanner built around local SHA-256 inspection. Select a folder, supply a signature database, and review exact matches with paths and digests. Export the results as JSON when the evidence needs to leave the application.

The project began as a Linux C implementation of directory traversal, executable filtering, hashing, and signature lookup. The Tauri desktop interface brings that core inspection workflow into a Rust backend with native folder selection and a visible results view.

## Demonstration

Use a harmless file and its known digest. Run the scan, show the matching record, and inspect the exported report. Change the file and repeat: the exact signature no longer matches. That is both the mechanism and the limitation, visible in one short demonstration.

## Intended use

AnnaKav is suited to learning endpoint inspection concepts, demonstrating signature matching, and checking controlled local datasets against supplied hashes. Its value is an inspectable workflow: file, digest, lookup, evidence.

It is not presented as production endpoint protection. There are no detection efficacy claims, customer metrics, or performance benchmarks to report yet. Unknown threats and modified samples require approaches beyond exact hash matching.

## Development direction

The next engineering priorities are scan progress and cancellation, richer signature provenance, checkpoint design, and validation across release platforms. Each adds practical value without pretending the current prototype already contains it.

AnnaKav makes a narrow claim that can be demonstrated: local files, explicit signatures, visible evidence. The next step is to make that workflow more useful, then measure what it can actually do.
