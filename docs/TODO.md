# Remaining work

Status against [SPEC.md](../SPEC.md).

## Needs another implementer

The assistant that wrote most of this repository could not complete these parts. They should be
implemented elsewhere; the assistant can still review, test, and fix them afterwards.

- [x] Apple account login (`src/apple/gsa.rs`, SPEC 9.2): SRP, trusted-device 2FA, Xcode token; live validation pending
- [ ] Developer Services client (`src/apple/developer.rs`, SPEC 9.4)
- [ ] Local ADI (`src/anisette/local_adi/`, SPEC 9.1)

## In progress here

- [ ] Install pipeline wiring and dry-run plan output (SPEC 7)
- [ ] Diagnostic commands wiring (SPEC 8)
- [ ] Device communication (`src/device/`, SPEC 10)

## Done

Credential input (no-echo password, 2FA prompt), CLI, configuration, formats (plist, zip, DER, JSON), crypto, HTTPS/WebSocket client,
`--sidestore` download, bundle processing, code signing, remote anisette v3.
