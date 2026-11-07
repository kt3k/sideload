# sideload

Sideload iOS apps onto a USB-connected device with a free or paid Apple developer account.

A reduced, corrected Rust port of the [Sideloader](https://github.com/Dadoum/Sideloader) CLI: an
`install` command plus the diagnostic commands needed when installation fails.

**Status:** early. Argument parsing, configuration resolution, argument validation, and the
format layer (plist XML/binary, ZIP, DER, JSON), crypto (SRP, AES, RSA), HTTP/WebSocket clients, remote anisette v3, the
`--sidestore` download, IPA/bundle processing, and the in-process code signer work. Apple
login/developer APIs and device communication are implemented; Linux local ADI is in partial
rollout (see docs/LOCAL_ADI.md). Diagnostic commands are wired; install pipeline wiring remains pending;
`install --output` is not wired up. See [docs/SIGNING.md](docs/SIGNING.md) for the signing API,
validation, and current limitations.

- [SPEC.md](SPEC.md): behavior specification
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): module map, dependency policy, reference sources
- [docs/REMOTE_ANISETTE.md](docs/REMOTE_ANISETTE.md): remote provider API and validation
- [docs/LOCAL_ADI.md](docs/LOCAL_ADI.md): how upstream generates anisette data locally

```sh
cargo build --release
./target/release/sideload --help
```

## License

MIT. Files ported from MPL-2.0 sources keep their MPL-2.0 notice (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#reference-sources-and-licenses)).
