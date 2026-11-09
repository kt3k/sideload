#!/bin/sh
# Builds the Rust core (ios/core) as a static library for the Xcode project.
# Usage: ios/build-core.sh [target]   (default: aarch64-apple-ios)
# Output: ios/build/lib/libsideload_ios_core.a
set -eu
here=$(cd "$(dirname "$0")" && pwd)
target=${1:-aarch64-apple-ios}
export IPHONEOS_DEPLOYMENT_TARGET=${IPHONEOS_DEPLOYMENT_TARGET:-16.0}
cd "$here/.."
cargo build -p sideload-ios-core --profile ios --target "$target" --locked
mkdir -p "$here/build/lib"
cp "target/$target/ios/libsideload_ios_core.a" "$here/build/lib/"
echo "Built $here/build/lib/libsideload_ios_core.a ($target)"
