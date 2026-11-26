# First public repair preview — proposed v0.1.0

- Repair case and evidence summary from November 2026.
- Read-only diagnostics (`--check`, `--list-ports`, `--demo`, `--analyze`, `--analyze-bundle`), including UDS warning-mask DTC reads and conditional read-only gear-adaptation / shift-force sensor DIDs (`0300`–`0308`, `013C`).
- Guided level-1 shift-force adaptation reset (`--l1-reset-now`) with capture-derived access provenance.
- Single-attempt journal, consent gates, keepalive lock isolation across unlock→reset, identity checks and adaptation-persistence verification.
- Offline regression tests and allowlisted ZIP build with `BUILD_COMMIT` and SHA-256 checksum.

## Limitations

The original workflow succeeded on one 2018 Tiger 1200 XRT. The public derivative has not been separately validated on hardware. No higher-level access, programming, flashing, gear adaptation reset or fault clearing is provided. No compatibility guarantee for other ECU revisions or models.

After a passing CI run, download the build artifact under Actions, create a GitHub prerelease tagged v0.1.0 and attach the ZIP and SHA256SUMS.txt. Do not copy Git history or logs from the private archive.
