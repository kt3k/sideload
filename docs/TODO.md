# Remaining work

Status against [SPEC.md](../SPEC.md).

## Needs another implementer

These service backends are tracked separately from the command/pipeline wiring below.
Checked items have implementation and mock coverage; live validation is noted explicitly.

- [x] Apple account login (`src/apple/gsa.rs`, SPEC 9.2): SRP, trusted-device 2FA, Xcode token; logged in to a real Apple ID on macOS with 0.1.4 (2026-11-08)
- [x] Developer Services client (`src/apple/developer.rs`, SPEC 9.4): all iOS operations and CSR; `listTeams` works live (0.1.4, macOS); the other operations await a real install
- [x] Local Anisette: Linux x86_64/aarch64 and Windows x64 Android ADI; macOS Intel/Apple Silicon native AOSKit/AuthKit. Live provisioning + OTP rotation pass on Linux x86_64/aarch64, Windows x64 and macOS arm64 runners (Live Anisette workflow); A real Apple ID login succeeded on macOS (0.1.4). Login with the Android ADI backends, macOS Intel and 16 KiB-page kernels pending.
- [ ] Anisette resync on GSA `hsc 434` / `X-Apple-I-MD-DATA` (needs an AnisetteProvider::resync hook; live-only)

## In progress here

- [ ] iOS app ([ios/SPEC.md](../ios/SPEC.md)): core, Swift UI, Shortcuts action, background
  refresh and CI build are implemented; install / refresh on a real device over LocalDevVPN
  is unverified (ios/SPEC.md Section 14, real integration).
- [ ] iOS app: on-device Anisette without a server (currently a non-goal, ios/SPEC.md 2.2 and
  4.4; the app needs a remote anisette-v3 server). SideStore does this with AnisetteKit, which
  runs the ADI libraries on the device under an emulator. Needs a decision before any work,
  and a spec update.


## Done

Install pipeline (all phases, dry-run plan, --output, device delivery), diagnostic commands (team/device/cert/app-id), device communication (usbmuxd, pairing records, lockdownd TLS session, AFC,
installation_proxy, misagent), credential input (no-echo password, 2FA prompt), CLI, configuration, formats (plist, zip, DER, JSON), crypto, HTTPS/WebSocket client,
`--sidestore` download, bundle processing, code signing, remote anisette v3.

## Known gaps against SPEC

- SPEC 16: an end-to-end check of the signed `--output` IPA is still untested (needs a
  signed fixture or a real certificate).
