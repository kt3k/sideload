# Code signing

`sign::sign_bundle` signs an extracted, prepared `bundle::AppBundle` in place. It takes:

- A `SigningIdentity`: RSA private key, team identifier, and DER certificates (signer first,
  then intermediates). The certificate's RSA public key must match the private key. Build it
  with `SigningIdentity::with_apple_chain`, which appends the Apple WWDR G3 intermediate (when it
  issued the certificate) and the Apple Root CA from `sign/certs/`, so that iOS can build the
  chain.
- A `BTreeMap<String, Vec<u8>>` from each app/extension's final bundle identifier to its own
  complete Apple-issued `.mobileprovision` bytes.
- A positive thread count. Independent embedded Mach-O files run in a bounded worker pool;
  child bundles always finish before their parent. `1` processes sequentially.

The caller must finish Info.plist rewriting before signing and must not change signed files
before repacking the IPA. Profiles are validated for all known apps/extensions before writes:
identifier coverage, matching team, and authorization of the signing certificate. The profile
parser extracts BER/CMS content; it does **not** verify Apple's CMS trust chain. Supply profiles
from the trusted Apple developer API, not arbitrary untrusted profile files.

Apps and extensions embed their own profile and derive XML and modern versioned DER
entitlements from it. Wildcard application identifiers and keychain groups are specialized.
Frameworks and dylibs are signed without application entitlements or embedded profiles. Nested
code is sealed before its containing bundle's CodeResources is generated. Resources use SHA-1
and SHA-256 seals; symlinks store their targets without following them.

`sign::sign_macho` is the lower-level byte API. It accepts optional final Info.plist,
CodeResources, and entitlements. It generates:

- SHA-1 and alternate SHA-256 CodeDirectories, 4 KiB page hashes, and special-slot hashes.
- A designated requirement binding identifier, Apple generic anchor, and certificate leaf OU.
- Detached CMS SignedData with SHA-256/RSA and Apple v1/v2 hash-agility attributes.
- Updated LC_CODE_SIGNATURE and __LINKEDIT file/VM sizes, hashing the finalized load commands.

Code is detected by magic: thin Mach-O magic always counts as code, but a fat magic
(`0xCAFEBABE` is shared with Java class files) only counts when the architecture table is small and
points at thin Mach-O slices inside the file; anything else is sealed as a resource. Nested bundles
must live in a location listed in `bundle::NESTED_BUNDLE_DIRS` (`PlugIns/`, `Extensions/`,
`Watch/`, `AppClips/`) so that they get their own App ID and profile.

Supported binaries are little-endian 32/64-bit Mach-O, including universal binaries with
32/64-bit fat headers in either byte order. Each architecture is signed independently.
Encrypted binaries, malformed/overlapping slices, non-final __LINKEDIT segments, existing
signatures outside the end of __LINKEDIT, and binaries without enough header padding for a
new LC_CODE_SIGNATURE are rejected. Executables must be ordinary files named by a single
CFBundleExecutable path component; versioned macOS frameworks with symlink executables are
not supported. This implementation targets iOS bundle layouts.

`sign_bundle` reports `signing_failed` in phase `Signing`, including the failing path. A
failure can leave the working bundle partially signed; discard it rather than repacking it.
Re-signing a successfully signed bundle is supported. Private keys are never included in
Debug output, errors, bundles, or profiles.

## Validation

Run the deterministic tests and the OpenSSL interoperability checks with:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

The OpenSSL checks run when `openssl` is installed (otherwise they report a skip). They verify
a detached CMS signature, reject modified content, and read a streaming BER profile created
by OpenSSL. Tests also cover both thin widths, universal binaries, re-signing, special/page
hashes, extension-specific profiles, frameworks/dylibs, parallelism, and invalid input.

An optional independent verifier test requires an installed `rcodesign` executable:

```sh
RCODESIGN=/path/to/rcodesign cargo test independent_rcodesign_verification -- --ignored
```

It checks signature verification, requirements/CMS decoding, and rejection of modified code
using apple-codesign 0.29.0. These checks use a self-signed test certificate and synthetic Mach-O
files; installing and launching a real app on iOS remains unverified. The test certificate was
created with OpenSSL from the repository's existing public test key; it is not an Apple identity.

`install` still needs Apple authentication, certificate/profile provisioning, and orchestration
before it can call this API. The sign module does not perform these account/device operations.
