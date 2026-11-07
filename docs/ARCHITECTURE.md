# Architecture

`SPEC.md` is the behavior contract. This document describes how the Rust implementation is
organized and what it depends on.

## Module map

| Layer (SPEC 3.2) | Module | Responsibility |
|---|---|---|
| Interface | `cli` | Argument parsing (`lexopt`), help text, exit codes |
| | `output` | Logs, progress, `error[<code>] (<phase>): ...` |
| Configuration | `config` | CLI > env > default resolution, configuration directory |
| | `credentials` | Apple ID, password, 2FA input |
| Coordination | `commands::install` | Install pipeline phases (SPEC 7) |
| | `commands::diagnostics` | `team` / `device` / `cert` / `app-id` (SPEC 8) |
| | `pipeline` | Phase and Mode vocabulary, Install Plan |
| Integration | `net::http` | HTTPS client over rustls (proxy, redirects, extra CAs) |
| | `sidestore` | `install --sidestore`: latest SideStore release from GitHub (SPEC 7.7) |
| | `anisette::{remote_v3, local_adi}` | Anisette headers (SPEC 9.1, docs/LOCAL_ADI.md) |
| | `apple::{gsa, developer}` | GrandSlam login, developerservices2 |
| | `device::{usbmuxd, lockdown, afc, installation_proxy, misagent}` | Device communication (SPEC 10) |
| Artifact | `bundle` | IPA extraction, bundle rewriting (SPEC 11.1) |
| | `sign` | Mach-O code signing (SPEC 11.2) |
| Building blocks | `formats::{plist, zip, der, json, base64, date}` | In-tree format code (implemented) |
| | `crypto::{cbc, srp, rsa_keygen}` | Protocol crypto on vetted primitives |

## Dependency policy

- Re-implement in-tree anything that is protocol or format code.
- Use external crates only for:
  - cryptographic primitives and TLS (never hand-rolled);
  - big-integer arithmetic;
  - compression;
  - small OS-portability helpers.
- Add a crate in the same change that first uses it.

Target set (33 crates including transitive dependencies on Linux, measured with `cargo tree`):

| Crate | Purpose | Added when |
|---|---|---|
| `lexopt` | CLI parsing (no dependencies) | now |
| `rustls` (ring, tls12) + `webpki-roots` | HTTPS and lockdown TLS. `ring` also provides SHA, HMAC, PBKDF2, RSA signing, and randomness | now (`net::http`, `crypto`) |
| `aes` | AES block cipher. CBC and GCM (16-byte IVs) are in-tree | now (`crypto`) |
| `num-bigint` (+ `num-integer`, `num-traits`) | SRP and RSA key generation | now (`crypto`) |
| `miniz_oxide` | Deflate | now (`formats::zip`) |
| `rpassword` | Password input without echo | `credentials` |
| `libc` | `mmap` / `mprotect` for local ADI (already transitive) | `anisette::local_adi` |

## Implementation order

1. `formats` (plist, zip, der) and `sign`, followed by `bundle` and `install --output` (verified
   by installing the output with an external tool).
2. `apple::http`, `anisette::remote_v3`, `apple::gsa`, and `apple::developer`, followed by the
   diagnostic commands.
3. `device`, followed by a full `install`.
4. `anisette::local_adi`.

## Reference sources and licenses

This project is MIT-licensed. Code may be ported only from MIT-compatible or file-level
licensed sources:

- MIT sources: keep the original copyright notice in the ported file.
- MPL-2.0 sources: the ported file stays under MPL-2.0. Keep the MPL header in that file; the
  rest of the project remains MIT.
- GPL, LGPL, and unlicensed sources: behavior reference only; never copy code.

| Source | License | Use |
|---|---|---|
| [nab138/isideload](https://github.com/nab138/isideload) | MIT | GSA, developer API, sideload flow |
| [jkcoxson/idevice](https://github.com/jkcoxson/idevice) | MIT | usbmuxd, lockdown, AFC, installation_proxy, misagent |
| [ebarnard/rust-plist](https://github.com/ebarnard/rust-plist) | MIT | plist formats |
| [SideStore/apple-private-apis](https://github.com/SideStore/apple-private-apis) (omnisette, icloud-auth) | MPL-2.0 | Anisette v3, GSA. Ported files keep MPL-2.0 |
| [indygreg/apple-platform-rs](https://github.com/indygreg/apple-platform-rs) (apple-codesign) | MPL-2.0 | Code signing. Ported files keep MPL-2.0 |
| apple-codesign-quick | LGPL-2.1-or-later | Do not port |
| [Dadoum/Sideloader](https://github.com/Dadoum/Sideloader) | GPL-3.0 | Behavior reference only. Do not copy |
| [Dadoum/Provision](https://github.com/Dadoum/Provision), [Dadoum/android-loader](https://github.com/Dadoum/android-loader) | no license file | Behavior reference only. Do not copy |
