Changelog
=========

## 0.8.1
- Added aarch64 (ARM64) release builds for Linux and macOS, including an aarch64 RPM.
- Bumped `pbkdf2` to 0.13 and `sha-crypt` to 0.6, migrating to the rewritten `password-hash` 0.6 API.
- Updated all package dependencies.

## 0.8.0
- Added `-m, --mnemonic [<words>]` to generate standard English BIP-39 recovery phrases with 12, 15, 18, 21, or 24 words.
- Added JSON output support for mnemonic generation.
- Reworked large password batch generation to use a bounded worker pool instead of one blocking task per password.
- Made password JSON output all-or-nothing on worker errors to avoid partial JSON results.
- Hardened custom symbol handling so multibyte symbol sets work correctly.
- Updated dependencies, GitHub workflows, and documentation.

## 0.7.0
- Using crossbeam channels to improve performance.

## 0.6.0
- Added option `-j, --json` to output the result as JSON.

## 0.5.0
- Added option `-c, --charset` to specify the charset of the input file.
