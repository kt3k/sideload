#!/bin/sh
# Install the latest `sideload` release binary for this platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kt3k/sideload/main/install.sh | sh
#
# Environment variables:
#   SIDELOAD_VERSION   release tag to install (default: latest)
#   SIDELOAD_BIN_DIR   install directory (default: ~/.local/bin)
#
# Windows is not covered by this POSIX script; download the .exe from the
# releases page instead.
set -eu

repo="kt3k/sideload"
version="${SIDELOAD_VERSION:-latest}"
bin_dir="${SIDELOAD_BIN_DIR:-$HOME/.local/bin}"

fail() {
	echo "install: $1" >&2
	exit 1
}

# Map uname output to a Rust target triple.
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
	Linux) os_part="unknown-linux-gnu" ;;
	Darwin) os_part="apple-darwin" ;;
	*) fail "unsupported OS '$os'; on Windows, download the .exe from https://github.com/$repo/releases" ;;
esac
case "$arch" in
	x86_64 | amd64) arch_part="x86_64" ;;
	arm64 | aarch64) arch_part="aarch64" ;;
	*) fail "unsupported CPU architecture '$arch'" ;;
esac
target="${arch_part}-${os_part}"
asset="sideload-${target}"

if [ "$version" = "latest" ]; then
	base="https://github.com/$repo/releases/latest/download"
else
	base="https://github.com/$repo/releases/download/$version"
fi
url="$base/$asset"

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 ||
	fail "need curl or wget"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ($version)..."
download() {
	# download <url> <output>
	if command -v curl >/dev/null 2>&1; then
		curl -fSL "$1" -o "$2"
	else
		wget -O "$2" "$1"
	fi
}
download "$url" "$tmp/sideload" ||
	fail "download failed; check that a release exists for $target at https://github.com/$repo/releases"

# Verify the checksum when the release publishes one.
if download "$url.sha256" "$tmp/sideload.sha256" 2>/dev/null; then
	expected="$(awk '{print $1}' "$tmp/sideload.sha256")"
	if command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum "$tmp/sideload" | awk '{print $1}')"
	elif command -v shasum >/dev/null 2>&1; then
		actual="$(shasum -a 256 "$tmp/sideload" | awk '{print $1}')"
	else
		actual=""
	fi
	if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
		fail "checksum mismatch (expected $expected, got $actual)"
	fi
	[ -n "$actual" ] && echo "Checksum verified."
fi

chmod +x "$tmp/sideload"
mkdir -p "$bin_dir"
mv "$tmp/sideload" "$bin_dir/sideload"
# macOS: clear the quarantine attribute on the downloaded binary.
if [ "$os" = "Darwin" ]; then
	xattr -d com.apple.quarantine "$bin_dir/sideload" 2>/dev/null || true
fi

echo "Installed sideload to $bin_dir/sideload"
case ":$PATH:" in
	*":$bin_dir:"*) ;;
	*) echo "Note: $bin_dir is not on your PATH; add it, e.g. export PATH=\"$bin_dir:\$PATH\"" ;;
esac
