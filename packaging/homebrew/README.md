# Homebrew tap setup

`sideload` is distributed through a personal tap, `kt3k/homebrew-tap`. Users install with:

```sh
brew install kt3k/tap/sideload
```

`sideload.rb` in this directory is the formula (builds from source with the `rust` toolchain). It
is kept here for version control; the tap itself lives in a separate repository.

## One-time: create the tap

The tap must be its own GitHub repository whose name starts with `homebrew-`:

```sh
# Create an empty public repo named kt3k/homebrew-tap, then:
git clone https://github.com/kt3k/homebrew-tap
cd homebrew-tap
mkdir -p Formula
cp /path/to/sideload/packaging/homebrew/sideload.rb Formula/sideload.rb
git add Formula/sideload.rb
git commit -m "Add sideload formula"
git push
```

`brew install kt3k/tap/sideload` resolves to `kt3k/homebrew-tap` → `Formula/sideload.rb`.

## Each release: update the formula

After tagging a release (e.g. `v0.1.0`), update `url` and `sha256` in `Formula/sideload.rb`:

```sh
tag=v0.1.0
url="https://github.com/kt3k/sideload/archive/refs/tags/$tag.tar.gz"
sha=$(curl -fsSL "$url" | shasum -a 256 | awk '{print $1}')
echo "url \"$url\""
echo "sha256 \"$sha\""
```

Commit the change to the tap repository. (This can be automated later with a release workflow that
opens a PR against the tap.)

## Notes

- On macOS, usbmuxd is built in, so the formula needs no runtime dependency.
- Local ADI is Linux-only; on macOS use `sideload --anisette-server <URL>`.
- Homebrew clears the download quarantine, so no `xattr` step is needed.
