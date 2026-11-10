# On-device Anisette implementation

The contract is [SPEC.md Section 4.4](SPEC.md#44-anisette). This remains an MIT implementation
using our own AArch64 interpreter and guest ELF loader. It has no AnisetteKit, Unicorn, QEMU,
JIT or private Apple framework dependency. References are the
[Arm architecture](https://developer.arm.com/documentation/ddi0487/latest/) and
[AArch64 ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst).
No external emulator implementation or proprietary ADI binary is included in the repository.

**Experimental: Apple provisioning, Anisette header generation, OTP rotation, saved-state
reopening and the credential-free Core API pass live under interpretation on Linux x86_64
and macOS Apple Silicon.
Real iOS account login and refresh remain unverified.**
Settings exposes `On Device (Experimental)` explicitly. Remote Server remains the default.
`Check Anisette` reports success only when the selected backend actually generates headers.

## Implementation

- `core/src/emulation.rs`, `emulation/scalar.rs`: bounded guest memory, register widths/NZCV,
  branches, immediate/register arithmetic and logic, bitfields, selects/conditional compare,
  multiply/divide, shifts/reverse/count, signed/pair/indexed loads/stores and TLS reads.
- `emulation/vector.rs`: integer Advanced SIMD arithmetic, multiplication, logic, comparisons,
  constants, widening/narrowing, shifts, lane transfers, bit-preserving FMOV, population count
  and structure loads/stores. Unsupported instructions, floating-point arithmetic and guest
  syscalls trap. This is the subset exercised by ADI, not a complete AArch64 implementation.
- `emulation/elf.rs`: reuses our checked ELF parser, maps guest data/BSS, resolves explicit
  symbols and AArch64 RELATIVE/ABS64/GLOB_DAT/JUMP_SLOT relocations. No native executable
  mappings or guest-address-to-host-pointer conversion. ELF constructors are not run implicitly;
  ADI entry points perform the supported initialization, as in the native CLI backend.
- `emulation/runtime.rs`: links the core/store libraries at guest addresses; imports dispatch
  through synthetic guest addresses. Unknown imports trap on use. It supplies a bounded heap
  with checked allocation/free/reallocation, byte/string operations, guest TLS/errno, virtual
  dlopen/dlsym, single-thread synchronization/once, crypto randomness, clocks and Android file
  metadata. It never calls the native CLI hooks or native ADI code.
- Guest file operations resolve only flat filenames under virtual `/adi`, mapped to a private
  directory. Absolute paths outside `/adi`, traversal, nested paths, directories and symlinks
  are rejected. Host open uses no-follow on Unix and creates files with mode 0600; no host
  umask is modified. At most 32 file handles are available, and each guest file is capped at 4 MiB. Android AArch64 `stat` layout is
  marshalled explicitly, independently of the host OS.
- Limits: 128 MiB aggregate guest mappings; 16 MiB heap with 4 MiB individual buffer limit;
  2 MiB stack; 4,096 import addresses; 8 KiB strings; 50 million guest instructions per ADI
  entry call, with a 20-second wall-clock limit checked during execution. Nested once initializers share the remaining budget and have bounded depth.
- `emulation/adi.rs`: implements the CLI `provisioning::Engine` with guest-only argument and
  output-buffer marshalling. Output buffers are copied before disposal, scratch allocations
  are released, and failed provisioning paths clean up ADI sessions.
- `core/src/local_anisette.rs`: explicitly acquires **AArch64** libraries, even on x86_64 test
  hosts, from Apple's official APK. It reuses the CLI identity/provisioning exchange/header
  formatting. Identity/libraries live under `data_dir/anisette-local`; provisioning operates
  on a private staging copy. Only successful header generation commits validated files back,
  with atomic per-file replacement. Failed generation leaves the saved provisioning state
  intact. Runtime/file handles drop before the staging directory is removed.
- Core config `anisette_mode: "local"` selects the Rust provider directly and ignores stored
  remote URLs. `"remote"` requires a URL. Omitted mode retains legacy remote/host-callback
  behavior. `prepare_anisette` requires no Apple ID/password and returns only `{"ready":true}`.
- The scoped Swift/C/Rust header callback remains available for alternate host engines. The
  built-in interpreter does not require it. Neither local path silently falls back to a server.
- Swift Settings provides the experimental selector and credential-free check. Existing
  remote preferences remain intact. First acquisition/provisioning should run in the foreground;
  the app's Application Support directory supplies file protection and backup exclusion.

## Validation performed

- Independent LLVM-assembled scalar/SIMD fixtures exercise overflow, sign/zero extension,
  register/SP/PC behavior, vector lane operations, interleaved memory transfers and writeback.
- Unit tests cover heap reuse/coalescing, invalid frees, string/buffer bounds, guest-to-import
  dispatch, instruction exhaustion, file traversal/symlink rejection, Android metadata layout,
  private staging rollback/commit, backend selection and no remote fallback.
- Official Apple AArch64 libraries, acquired separately, run on this Linux x86_64 host through
  the interpreter: library path, provisioning path and identifier initialization return zero;
  a fresh state query returns ADI `-45061` (not provisioned); malformed synthetic SPIM is rejected
  through the ADI error path. These checks perform no Apple provisioning network exchange.

Reproduce deterministic tests:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
zig cc -target aarch64-linux-gnu -c ios/core/tests/fixtures/aarch64-extended.S -o /tmp/aarch64.o
SIDELOAD_AARCH64_ADI_LIBRARY_DIR=/path/to/official/arm64-v8a \
  cargo test -p sideload-ios-core --test interpreted_adi \
  official_libraries_initialize_and_reject_invalid_spim -- --ignored
cargo run -p sideload-ios-core --example adi_probe -- /path/to/official/arm64-v8a
```

## Live validation

The opt-in [Live interpreted Anisette workflow](../.github/workflows/live-interpreted-anisette.yml)
provisions a fresh synthetic identity and exercises the actual `LocalAnisette` provider. Main
pushes do not trigger this network test; it runs manually or on the dedicated verification
branch. It requires no Apple ID/password and never uploads generated state or header values.

On 2026-11-09, the [Linux x86_64 run](https://github.com/kt3k/sideload/actions/runs/42626305687)
passed first provisioning with Apple, required non-empty/base64 headers, repeated requests,
provider reopening from committed state with the same machine identity, OTP rotation after
35 seconds, and `prepare_anisette` without credentials or a usable remote server URL.
The [cross-platform run](https://github.com/kt3k/sideload/actions/runs/42626727790) then passed
the same complete test on both Linux x86_64 and macOS Apple Silicon (`aarch64-apple-darwin`).

The first live run exposed ADI filesystem error `-45054`: the interpreter rejected Android's
`O_LARGEFILE` flag. ADI writes with flags `0x8041` and reads with `0x8000`. The runtime now
accepts the guest flag as a no-op for its 64-bit file API, without passing Android flags to the
host OS. The unit file-I/O regression includes the flag; the subsequent live run passed.

Optional `SIDELOAD_GUEST_FS_TRACE=1` logs only static file operation names, open flags and
return statuses, never guest paths or buffer/header contents. It is disabled by default.

Reproduce the full live test explicitly:

```sh
SIDELOAD_AARCH64_ADI_LIBRARY_DIR=/path/to/official/arm64-v8a \
  cargo test -p sideload-ios-core --profile ios --test interpreted_adi \
  live_provisioning_rotation_and_persisted_provider -- --ignored --nocapture
```

## Remaining device validation

The opt-in developer probe below contacts Apple's provisioning API using a newly generated
local identity; it requires no Apple ID/password and does not log header values or blobs:

```sh
cargo run -p sideload-ios-core --release --example anisette_live -- \
  /path/to/official/arm64-v8a /path/to/private/test-state
```

Host live tests establish provisioning/OTP behavior, not real iOS account acceptance or
background execution. Before promoting local mode, verify on an ordinary iOS device without
JIT/debug entitlements: first acquisition, real account login, IPA install/refresh, relaunch,
Shortcuts while locked, interrupted setup and offline retry.

Crash recovery for abandoned staging directories and multi-file transactional checkpoints are
not implemented; files are committed atomically individually. Do not describe this backend as
stable or enable it by default until these live/device checks pass.

## Account sign-in diagnostics (-80045)

Header generation is not an account sign-in test. On 2026-11-10 a real-device report showed
Apple error `-80045` during login. The Android ADI identity previously advertised macOS; the
same legacy label reproduces `-80045` during password-free SRP init with a reserved `.invalid`
identity on both Linux and macOS ([diagnostic run](https://github.com/kt3k/sideload/actions/runs/42728198409)).
A [related client-info correction](https://github.com/arxdeus/xcross/pull/127) reports the same
mismatch. This is evidence of a protocol mismatch, not proof that it explains every rejection.

The local backend now advertises Android. Existing default Mac labels are corrected in memory
without deleting device IDs or provisioning. The HTTP headers remain strings, while GSA's CPD
flags are plist booleans and routing info is a plist integer. Apple's published G3 root is also
trusted for Android-selected authentication hosts; TLS verification remains enabled.

The reserved invalid identity still received HTTP 403 with the corrected profile and typed CPD.
That diagnostic cannot establish whether an actual account will be accepted. The probe stops
after SRP init: it sends no password, M1 proof or 2FA request, and logs no headers or challenge
values. It is deliberately a diagnostic command rather than a successful-login assertion:

```sh
cargo run -p sideload-ios-core --profile ios --example gsa_identity_probe -- \
  /path/to/official/arm64-v8a
```

`Check Anisette` continues to mean generation/provisioning only. Actual iOS account sign-in
with the corrected build remains unverified. Do not treat successful provisioning or a completed
diagnostic probe as a confirmed fix for account-side authentication errors.


## Authentication compatibility update

Remote mode offers explicit presets for mac-ani.jkcoxson.com, ani.jkcoxson.com and
ani.iloader.app. Choosing a provider clears the cached login session while retaining
saved credentials. There is no automatic fallback from on-device mode. Android ADI
generation can succeed while Apple rejects account login; local remains experimental.

Remote provisioning is bound to the server's client info and matching User-Agent.
Each GSA operation uses fresh Anisette in both its headers and CPD, and sign-in pins
the same identity. Remote SRP init resynchronization (`hsc 434`) retries once with
Apple's machine data, retaining the same provider and identity; unsupported providers
fail explicitly. Local resynchronization remains pending.

An automatic `hsc 409` challenge without `au` uses the already delivered code without
requesting another. SMS uses Apple's JSON authentication endpoints and the first valid
phone ID from account metadata; it never assumes phone ID 1. Wrong codes may be retried
and resend requires user action. Successful verification is followed by fresh SRP login.
These paths have mock regression coverage. Real iOS account login and SMS remain
unverified; successful Anisette generation alone does not establish authentication.
