# Attachment codec memory measurements

The `attachment_allocations` example measures the public attachment codec with synthetic bytes. It performs no HTTP requests and prints only operation names, sizes, concurrency, and elapsed time. Use the release executable directly so Cargo and compilation do not contribute to the process peak. When sharing a Cargo target between checkouts, refresh the measured workspace source timestamps before each build, confirm Cargo recompiles those workspace crates, and save each executable immediately. Verify that baseline and optimized executable hashes differ before measuring; a reused executable is not a valid comparison. Run each payload size in a fresh process with concurrency one.

Upload includes plaintext allocation, SHA-256, metadata encryption, authenticated blob encryption, base64 encoding, owned JSON assembly, and JSON body serialization. Download includes reading a ciphertext fixture, JSON parsing, metadata and key verification, base64 decoding, and authenticated decryption. Generate its fixture in a separate process so upload allocations cannot contribute to the download peak. Runtime startup and system allocator behavior are included; HTTP buffers and transport-envelope handling are excluded.

## Reproduce

```sh
cargo build --locked --release -p seren-secrets-resolver --example attachment_allocations
/usr/bin/time -l target/release/examples/attachment_allocations --operation upload --size 10485760
target/release/examples/attachment_allocations --operation fixture --size 10485760 --fixture /tmp/synthetic-attachment.json
/usr/bin/time -l target/release/examples/attachment_allocations --operation download --size 10485760 --fixture /tmp/synthetic-attachment.json
```

On macOS, `maximum resident set size` is bytes. On Linux, use `/usr/bin/time -v` and convert its maximum resident set size from KiB to bytes. Record the compiler version, target platform, release profile, payload bytes, operation, and concurrency with the results. Keep generated ciphertext fixtures outside the repository and never substitute real vault data.

Measure 1,024, 1,048,576, 10,485,760, and 104,857,558 plaintext bytes. The last size fills the public 100 MiB encrypted limit, including the unchanged 42-byte envelope. The 500 MiB aggregate limit remains unchanged.

For a baseline comparison, use the source at `3367bbb88421e54a841beb499129a0c9fd360e3d` with this same harness. Adapt its required content-type field by removing `Some(...)` and replace `serde_json::Value::from(pending.encrypt())` with `serde_json::to_value(pending.encrypt())?`. These adapters use the original public APIs; they do not replace library implementations. Copy the measured tree's `Cargo.lock` into the baseline snapshot and build both with `--locked`, so both builds use an identical dependency graph and differ only in workspace source and the two adapters. The baseline manifests resolve to the same graph. Use the same compiler, profile, payload sizes, fixtures, and concurrency for both builds. The new owned conversion moves encrypted strings into JSON, and envelope encryption reserves one buffer instead of allocating intermediate ciphertext and nonce-prefixed payload buffers.
## Measured peak memory

Measured on 2026-10-20 with rustc 1.99.1 (`58cf8f9c3`, LLVM 23.1.1), `aarch64-apple-darwin`, macOS 27.0.1, and Apple M2. Both builds used the default Cargo release profile, the same dependency lockfile, and concurrency one. Each cell is the median of three fresh-process runs; baseline and optimized executions alternated for each operation and size. Sizes below are plaintext bytes; RSS is shown in MiB (1,048,576 bytes).

| Plaintext bytes | Operation | Baseline peak MiB | Optimized peak MiB |
| ---: | --- | ---: | ---: |
| 1,024 | upload | 5.59 | 5.55 |
| 1,024 | download | 5.59 | 5.56 |
| 1,048,576 | upload | 12.38 | 10.28 |
| 1,048,576 | download | 9.31 | 9.28 |
| 10,485,760 | upload | 72.36 | 52.30 |
| 10,485,760 | download | 42.34 | 42.31 |
| 104,857,558 | upload | 672.30 | 472.31 |
| 104,857,558 | download | 372.33 | 372.30 |

At the maximum payload, upload peak RSS fell by about 200 MiB (29.7%) on this host. Download peak RSS was effectively unchanged; the small differences are within process and allocator variability. These codec measurements do not measure the moved HTTP transport-envelope parsing or establish a bound on a complete client process. Repeat on each target platform before using these values for capacity planning.
