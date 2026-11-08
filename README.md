# sideload

Sideload iOS apps onto a USB-connected device with a free or paid Apple developer account.

A reduced, corrected Rust port of the [Sideloader](https://github.com/Dadoum/Sideloader) CLI: an
`install` command plus the diagnostic commands needed when installation fails.

**Status:** feature-complete, pending live validation. The full `install` pipeline, the
diagnostic commands, code signing, the Apple login / Developer Services clients, remote anisette
v3, local Anisette on Linux/macOS/Windows, and device communication are implemented. Deterministic
paths have unit tests; local Anisette provisioning and OTP generation pass live on Linux
(x86_64/aarch64), Windows x64 and macOS arm64 CI runners. Logging in to a real Apple account and
installing onto a real device remain unverified. See
[docs/TODO.md](docs/TODO.md).

- [SPEC.md](SPEC.md): behavior specification
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): module map, dependency policy, reference sources
- [docs/TODO.md](docs/TODO.md): what remains
- [docs/SIGNING.md](docs/SIGNING.md), [docs/REMOTE_ANISETTE.md](docs/REMOTE_ANISETTE.md), [docs/LOCAL_ADI.md](docs/LOCAL_ADI.md): subsystem notes

## Installation

With [Homebrew](https://brew.sh) (macOS, or Linux):

```sh
brew install kt3k/tap/sideload
```

Otherwise, on Linux and macOS, the install script detects your platform, downloads the matching
binary from the latest release, verifies its checksum, and installs it to `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/kt3k/sideload/main/install.sh | sh
```

Set `SIDELOAD_VERSION` to pin a release tag or `SIDELOAD_BIN_DIR` to change the install directory.

Or download a binary yourself from the
[latest release](https://github.com/kt3k/sideload/releases/latest) (targets:
`x86_64`/`aarch64-unknown-linux-gnu`, `x86_64`/`aarch64-apple-darwin`,
`x86_64-pc-windows-msvc.exe`); each asset has a matching `.sha256`:

```sh
curl -L -o sideload https://github.com/kt3k/sideload/releases/latest/download/sideload-x86_64-unknown-linux-gnu
chmod +x sideload
sudo mv sideload /usr/local/bin/
sideload --help
```

On macOS, an unsigned binary is quarantined by Gatekeeper; the install script clears it, or do it
yourself with `xattr -d com.apple.quarantine sideload`. On Windows, download the `.exe` from the
releases page.

To talk to a device you also need the USB multiplexer: `usbmuxd` on Linux
(`sudo apt install usbmuxd`), built in on macOS, and Apple Mobile Device Support (bundled with
iTunes) on Windows.

Or build from source:

```sh
cargo build --release
./target/release/sideload --help
```

## Usage

```sh
# Install an IPA onto the connected device (prompts for Apple ID, password and 2FA code)
sideload install MyApp.ipa

# Install the latest SideStore release from GitHub
sideload install -s

# Show what would be registered and signed, without changing anything
sideload install MyApp.ipa --dry-run

# Sign only and write the result instead of installing
sideload install MyApp.ipa -o MyApp-signed.ipa
```

Other `install` options: `--udid`, `--team`, `--strip-extensions` (saves App IDs on free
accounts), `--bundle-id`, `--name`, `--new-cert`, `--keep-temp`. See `sideload install --help`.

When installation fails, the diagnostic commands show the account state: `team list`,
`device list` / `device delete`, `cert list` / `cert revoke`, `app-id list` / `app-id delete`.

Credentials can be passed with `SIDELOADER_APPLE_ID` and `SIDELOADER_APPLE_PASSWORD` instead of
the prompts (the password may then be readable by other processes of the same user).

### Anisette

Apple login needs anisette data. Local generation uses Apple's Android ADI libraries on Linux
(x86_64/aarch64) and Windows (x86_64), downloaded automatically. macOS (Intel/Apple Silicon)
uses the system AOSKit/AuthKit frameworks without downloading Android libraries. If a native
backend is unavailable or fails, use a remote anisette-v3 server:

```sh
sideload --anisette-server https://ani.example.com install MyApp.ipa
# or: export SIDELOADER_ANISETTE_SERVER=https://ani.example.com
```

A remote server is a third party that generates anisette data with device identifiers; use one
you trust.

## Releasing

Bump `version` in `Cargo.toml`, push to `main`, then run the **Tag release** workflow
(Actions tab, input e.g. `v0.1.2`). It tags `main`, creates the GitHub Release and dispatches
`release.yml`, which attaches the binaries. Then update the Homebrew formula
(see [packaging/homebrew/README.md](packaging/homebrew/README.md)).

## License

MIT. Files ported from MPL-2.0 sources keep their MPL-2.0 notice (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#reference-sources-and-licenses)).
