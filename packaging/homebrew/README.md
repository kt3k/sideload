# Homebrew tap setup

`sideload` is distributed through a personal tap, `kt3k/homebrew-tap`. Users install with:

```sh
brew install kt3k/tap/sideload
```

`sideload.rb` in this directory is a copy of the tap's formula (builds from source with the `rust`
toolchain), kept here for reference; the tap's copy is the one Homebrew uses.

## Tap layout

The tap is the GitHub repository `kt3k/homebrew-tap`, with formulae at the top level (next to
`saku.rb`). `brew install kt3k/tap/sideload` resolves to `kt3k/homebrew-tap` → `sideload.rb`.

## Each release: update the formula

After the release tag exists (e.g. `v0.1.2`), update `url`, `sha256` and `version` in the tap's
`sideload.rb`, then copy it back here:

```sh
tag=v0.1.2
url="https://github.com/kt3k/sideload/archive/refs/tags/$tag.tar.gz"
sha=$(curl -fsSL "$url" | shasum -a 256 | awk '{print $1}')
echo "url \"$url\""
echo "sha256 \"$sha\""
```

Commit the change to the tap repository. (This could later be automated with a workflow that
opens a PR against the tap.)

## Notes

- On macOS, usbmuxd is built in, so the formula needs no runtime dependency.
- Local ADI is Linux-only; on macOS use `sideload --anisette-server <URL>`.
- Homebrew clears the download quarantine, so no `xattr` step is needed.
