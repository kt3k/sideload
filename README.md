# sideload

Sideload iOS apps onto a USB-connected device with a free or paid Apple developer account.

A reduced, corrected Rust port of the [Sideloader](https://github.com/Dadoum/Sideloader) CLI: an
`install` command plus the diagnostic commands needed when installation fails.

**Status:** scaffold. Argument parsing, configuration resolution, and argument validation work.
Everything else is not implemented yet.

- [SPEC.md](SPEC.md): behavior specification
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): module map, dependency policy, reference sources
- [docs/LOCAL_ADI.md](docs/LOCAL_ADI.md): how upstream generates anisette data locally

```sh
cargo build --release
./target/release/sideload --help
```
