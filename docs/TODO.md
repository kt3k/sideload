# Remaining work

Status against [SPEC.md](../SPEC.md).

## Needs another implementer

These service backends are tracked separately from the command/pipeline wiring below.
Checked items have implementation and mock coverage; live validation is noted explicitly.

- [x] Apple account login (`src/apple/gsa.rs`, SPEC 9.2): SRP, trusted-device 2FA, Xcode token; live validation pending
- [x] Developer Services client (`src/apple/developer.rs`, SPEC 9.4): all iOS operations and CSR; live validation pending
- [ ] Local ADI (`src/anisette/local_adi/`, SPEC 9.1): Linux loader/provisioning implemented and x86_64 initialization checked; macOS/Windows and live OTP validation remain
- [ ] Anisette resync on GSA `hsc 434` / `X-Apple-I-MD-DATA` (needs an AnisetteProvider::resync hook; live-only)

## In progress here

- [ ] Install pipeline wiring and dry-run plan output (SPEC 7)

## Done

Diagnostic commands (team/device/cert/app-id), device communication (usbmuxd, pairing records, lockdownd TLS session, AFC,
installation_proxy, misagent), credential input (no-echo password, 2FA prompt), CLI, configuration, formats (plist, zip, DER, JSON), crypto, HTTPS/WebSocket client,
`--sidestore` download, bundle processing, code signing, remote anisette v3.
