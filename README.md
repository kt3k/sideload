# sideload

Sideload iOS apps onto a USB-connected device with a free or paid Apple developer account.

A reduced, corrected Rust port of the [Sideloader](https://github.com/Dadoum/Sideloader) CLI: an
`install` command plus the diagnostic commands needed when installation fails.

**Status:** feature-complete, pending live validation. The full `install` pipeline, the
diagnostic commands, code signing, the Apple login / Developer Services clients, remote anisette
v3, Linux (x86_64/aarch64) local ADI, and device communication are all implemented and covered by
unit tests against mock transports. End-to-end installation against a real Apple account and
device has not been run yet, and local ADI on macOS/Windows is not done. See
[docs/TODO.md](docs/TODO.md).

- [SPEC.md](SPEC.md): behavior specification
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): module map, dependency policy, reference sources
- [docs/TODO.md](docs/TODO.md): what remains
- [docs/SIGNING.md](docs/SIGNING.md), [docs/REMOTE_ANISETTE.md](docs/REMOTE_ANISETTE.md), [docs/LOCAL_ADI.md](docs/LOCAL_ADI.md): subsystem notes

## Installation

Download the binary for your platform from the
[latest release](https://github.com/kt3k/sideload/releases/latest):

```sh
# Linux x86_64 (also: aarch64-unknown-linux-gnu, x86_64/aarch64-apple-darwin,
# x86_64-pc-windows-msvc.exe)
curl -L -o sideload https://github.com/kt3k/sideload/releases/latest/download/sideload-x86_64-unknown-linux-gnu
chmod +x sideload
sudo mv sideload /usr/local/bin/
sideload --help
```

Each asset has a matching `.sha256`. On macOS, an unsigned binary is quarantined by Gatekeeper;
clear it with `xattr -d com.apple.quarantine sideload`.

To talk to a device you also need the USB multiplexer: `usbmuxd` on Linux
(`sudo apt install usbmuxd`), built in on macOS, and Apple Mobile Device Support (bundled with
iTunes) on Windows.

Or build from source:

```sh
cargo build --release
./target/release/sideload --help
```

## License

MIT. Files ported from MPL-2.0 sources keep their MPL-2.0 notice (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#reference-sources-and-licenses)).
