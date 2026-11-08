# How upstream Sideloader does local ADI

Notes from reading Sideloader (`source/app/package.d`, `source/server/appleaccount.d`) and its
dependency [Dadoum/Provision](https://github.com/Dadoum/Provision) at commit `645d56d`
(`lib/provision/{androidlibrary,adi,symbols}.d`, `lib/provision/compat/*.d`).

**License note.** Sideloader is GPL-3.0. Provision ships no license file, which means all rights
reserved. Neither may be copied into this repository. This document describes *behavior* (file
names, endpoints, exported symbol names, data flow) so that the Rust implementation can be
written independently.

## 1. Where the ADI code comes from

ADI ("Apple Device Identification") is Apple's closed-source anisette generator. Apple ships it
inside several apps; Provision uses the **Apple Music for Android** APK because it has the most
architectures and exposes entry points to set the identifier and the library path.

- APK URL: `https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk`
  (about 150 MB).
- Extract two files for the host architecture into `<config>/lib/`:
  - `lib/<abi>/libstoreservicescore.so`
  - `lib/<abi>/libCoreADI.so`
- ABI directory per host architecture: `x86_64`, `x86`, `arm64-v8a`, `armeabi-v7a`.

The libraries are Android (bionic) ELF shared objects. They cannot be `dlopen`ed by glibc, so
Provision ships its own loader.

## 2. The loader (`AndroidLibrary`)

A small ELF loader that runs the Android library inside the host process:

1. `mmap` the file and parse the ELF header and program headers.
2. Compute the span of all `PT_LOAD` segments and reserve one anonymous mapping for it.
3. Copy each segment to `base + p_vaddr`, zero-fill `p_memsz - p_filesz`, and `mprotect`
   according to `p_flags`.
   - When the host page size is larger than 4 KiB (for example 16 KiB on Asahi Linux or some
     aarch64 kernels), adjacent segments can share a page with incompatible protections.
     Provision shifts the load base so that they do not, and gives up if that is impossible.
4. Parse the dynamic section: `.dynsym`, `.dynstr`, the hash table, and the relocation tables.
5. Apply the `REL` and `RELA` relocation sections. Only four types are handled, and any other type
   is a load error: `RELATIVE` (base + addend), `GLOB_DAT`, `JUMP_SLOT`, and the native absolute
   type (`R_X86_64_64` or `R_AARCH64_ABS64`). Symbols are resolved in this order:
   1. the hook table (below);
   2. symbols of other Android libraries it has already loaded;
   3. otherwise, a stub that raises "undefined symbol <name>" when called.
6. `load(name)` looks up an exported symbol through the hash table and returns its address.

### Hook table (bionic replacements)

The Android code imports a small libc surface. Each import is redirected to a host function
(with tracing in debug builds):

| Import | Implementation |
|---|---|
| `open`, `close`, `read`, `write`, `mkdir`, `chmod`, `umask`, `ftruncate` | host libc |
| `lstat`, `fstat` | host libc, converted to the **Linux `struct stat` layout** on macOS and Windows |
| `malloc`, `free`, `strncpy`, `gettimeofday` | host libc |
| `__errno` | host `errno` location (`__errno_location` on Linux) |
| `arc4random` | host random number generator |
| `__system_property_get` | returns a fixed string (`"no s/n number"`) |
| `dlopen`, `dlsym`, `dlclose` | wrappers that load or resolve **other Android libraries with this same loader**. This is how `libstoreservicescore.so` pulls in `libCoreADI.so` |
| `pthread_once`, `pthread_create`, `pthread_mutex_*`, `pthread_rwlock_*` | empty stubs (everything runs on one thread) |

### Calling convention

The Android libraries use the System V AMD64 ABI (or AAPCS64 on arm64).

- On Linux and macOS (x86_64) this matches the host, so calls are direct.
- On Windows (x86_64) every call into the library goes through a System V trampoline, and every
  hook is declared with the System V calling convention. Provision also adapts the CRT functions
  (`_read`, `_write`, `_chsize`, `_mkdir`, ...) and the `stat` layout. This is how upstream
  supports local ADI on Windows.

In Rust, the equivalents are `extern "sysv64" fn` for x86_64 hooks and function pointers, and
`extern "C"` on aarch64 Linux.

## 3. The ADI API

`libstoreservicescore.so` exports the ADI functions under obfuscated but stable names:

| Symbol | Function | Signature (C) |
|---|---|---|
| `kq56gsgHG6` | LoadLibraryWithPath | `int (const char *path)` |
| `Sph98paBcz` | SetAndroidID | `int (const char *id, uint32_t len)` |
| `nf92ngaK92` | SetProvisioningPath | `int (const char *path)` |
| `p435tmhbla` | ProvisioningErase | `int (uint64_t dsid)` |
| `tn46gtiuhw` | Synchronize | `int (uint64_t dsid, uint8_t *sim, uint32_t sim_len, uint8_t **mid, uint32_t *mid_len, uint8_t **srm, uint32_t *srm_len)` |
| `fy34trz2st` | ProvisioningDestroy | `int (uint32_t session)` |
| `uv5t6nhkui` | ProvisioningEnd | `int (uint32_t session, uint8_t *ptm, uint32_t ptm_len, uint8_t *tk, uint32_t tk_len)` |
| `rsegvyrt87` | ProvisioningStart | `int (uint64_t dsid, uint8_t *spim, uint32_t spim_len, uint8_t **cpim, uint32_t *cpim_len, uint32_t *session)` |
| `aslgmuibau` | GetLoginCode | `int (uint64_t dsid)`. Returns 0 when provisioned and -45061 when not |
| `jk24uiwqrg` | Dispose | `int (void *ptr)`. Frees buffers returned by the other functions |
| `qi864985u0` | OTPRequest | `int (uint64_t dsid, uint8_t **mid, uint32_t *mid_len, uint8_t **otp, uint32_t *otp_len)` |

- A return value of 0 means success. ADI errors are -45xxx; FairPlay errors (-42xxx) can also
  appear.
- Sideloader always uses `dsid = -2` (as an unsigned 64-bit value).

Initialization order:

1. Load `libstoreservicescore.so` and resolve the symbols.
2. Call `LoadLibraryWithPath(<config>/lib)`.
3. Call `SetProvisioningPath(<config>)` (ADI keeps its state files there).
4. Call `SetAndroidID(adiIdentifier)`.

## 4. Device identity (`<config>/device.json`)

Created once, with random values, and then reused:

| Field | Value |
|---|---|
| `serverFriendlyDescription` | `<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>` (sent as `X-Mme-Client-Info`) |
| `uniqueDeviceIdentifier` | random UUID, uppercase (`X-Mme-Device-Id`) |
| `adiIdentifier` | 8 random bytes as lowercase hex (16 characters), passed to SetAndroidID |
| `localUserUUID` | 32 random bytes as uppercase hex (64 characters) (`X-Apple-I-MD-LU`) |

## 5. Provisioning (once per machine)

If `GetLoginCode(-2)` reports "not provisioned":

1. `GET https://gsa.apple.com/grandslam/GsService2/lookup` and read the URL bag (`urls` dict).
2. `POST urls["midStartProvisioning"]` with a plist body `{Header: {}, Request: {}}`. The
   response contains `spim` (base64).
3. `ProvisioningStart(-2, spim) -> (cpim, session)`.
4. `POST urls["midFinishProvisioning"]` with `{Header: {}, Request: {cpim: base64(cpim)}}`. The
   response contains `ptm`, `tk` (base64), and `X-Apple-I-MD-RINFO`.
5. `ProvisioningEnd(session, ptm, tk)`. On failure, `ProvisioningDestroy(session)`.

Headers on these requests:

- `User-Agent: akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0`
- `Content-Type: application/x-www-form-urlencoded`
- `X-Mme-Device-Id`, `X-MMe-Client-Info`, `X-Apple-I-MD-LU` (from `device.json`)
- `X-Apple-Client-App-Name: Setup`
- `X-Apple-I-Client-Time` (ISO 8601, no milliseconds)

## 6. Producing anisette headers (every request)

`OTPRequest(-2) -> (mid, otp)`, then:

- `X-Apple-I-MD` = base64(otp)
- `X-Apple-I-MD-M` = base64(mid)
- `X-Apple-I-MD-RINFO` = `17106176`
- `X-Apple-I-MD-LU` = `localUserUUID`
- `X-Mme-Device-Id` = `uniqueDeviceIdentifier`
- `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `X-Apple-Locale`, `X-Apple-I-SRL-NO: 0`

When Apple answers with `X-Apple-I-MD-DATA` (a resync request), call `Synchronize` and retry.

## 7. Platform support upstream

Sideloader's CI (`.github/workflows/build-cli.yml`) builds the CLI for five targets, and Provision
has a compatibility layer for each OS:

| Host | Library ABI loaded | What Provision adds | Notes |
|---|---|---|---|
| Linux x86_64 | `x86_64` | nothing (same ABI and `stat` layout) | the reference platform |
| Linux aarch64 | `arm64-v8a` | nothing | 16 KiB page kernels need the load shift (Section 2) |
| Windows x86_64 | `x86_64` | System V trampoline for every call (`androidInvoke`), `sysv_abi` hooks, CRT shims, Linux `stat` conversion | source comment: "Works on a real Windows machine, but not Wine". Windows on ARM is not handled |
| macOS x86_64 | `x86_64` | `errno` hook, Linux `stat` conversion | |
| macOS arm64 | `arm64-v8a` | same as macOS x86_64 | built in CI; whether it runs reliably (Darwin arm64 ABI and memory-protection differences) is unverified upstream. This repository uses AOSKit on macOS instead (Section 10) |

Being built in CI does not prove that a target works at runtime. Only the source code was read
for this document; nothing was run.

## 8. Implications for this repository

- Rust code size: an ELF64 loader with relocations, the hook table, and the ADI wrappers.
  Estimated at about 1,200 lines. Only `libc` is needed for `mmap` and `mprotect` (`VirtualAlloc`
  and `VirtualProtect` on Windows).
- Supported hosts (SPEC 9.1): Linux x86_64 / aarch64, macOS x86_64 / arm64, Windows x86_64.
  Rollout order, with the remote provider covering every platform in the meantime:
  1. Linux x86_64 and aarch64.
  2. macOS x86_64 and arm64: `errno` hook and Linux `stat` conversion. On arm64, check two
     things against the Darwin arm64 ABI: executable anonymous memory (`MAP_JIT` /
     `pthread_jit_write_protect_np` may be required) and bionic's TLS layout (`tpidr_el0` slots
     such as the stack guard), which macOS does not provide.
  3. Windows x86_64: `extern "sysv64"` hooks and trampolines, CRT and `stat` shims.
- Keep the upstream file layout (`<config>/lib/*.so`, `<config>/device.json`, and ADI state under
  `<config>`), so that the contents of a Sideloader configuration directory copied into this
  tool's `Sideload` directory are reused as-is.

## 9. Current implementation in this repository

`anisette::provider` now selects `local_adi::LocalAdi` when no remote server is configured.
The backend is native AOSKit/AuthKit on macOS Intel/Apple Silicon, and Android ADI on
Linux x86_64/aarch64 and Windows x64. Live provisioning and OTP generation pass on GitHub's
Linux x86_64, Linux aarch64, Windows x64 and macOS arm64 runners (see "Live validation"
below). macOS Intel is cross-compiled only (no Intel runner). Unsupported CPU/OS combinations
return an actionable error.

On first use of an Android backend, `download::ensure` obtains Apple's HTTPS APK, extracts only the architecture's
two libraries, validates ELF metadata, and installs each with a private temporary file and
rename under `config/lib`. Progress is printed at 0%, every 10% of the APK download (or every
10 MiB when the server sends no length), and 100% once the libraries are installed. The proprietary libraries are not redistributed in this repository.
Existing library files are reused. Treat this directory as executable code, not untrusted input.

The loader checks ELF64 program headers, file-backed dynamic addresses, symbol/relocation
bounds, machine type, and relocation kinds before mapping. It applies REL/RELA relocations and
separates executable from writable pages; incompatible large-page segment layouts fail rather
than creating writable/executable pages. General ELF constructors and TLS segments are not
supported. This loader is specifically for the ADI entry points, not the rest of Apple Music.

Native calls stay on the owning thread. The bionic hooks expose a narrow Linux libc ABI surface,
implement Android dlopen/dlsym only for the owned CoreADI mapping, and keep Android pthread
objects away from glibc. Thread creation fails with ENOSYS. Unresolved imports point to an
abort trap; calling unsupported portions of the Android libraries terminates the process.
The initialization smoke test exercises the required ADI setup and an unprovisioned-state query.
It does not establish that every later vendor-code path is compatible.

`device.json` uses the upstream field names and reuses an existing valid identity. New Unix files
are private (0600); Windows files inherit the user profile directory ACL. ADI's provisioning files are kept under `config/lib`, matching SPEC 4.1.1.
Provisioning relays Apple's lookup/start/finish exchange directly, destroys native sessions
on failure, and produces fresh machine/OTP headers. This protocol is tested with fake native
and Apple transports. Device identity, native buffers, and ADI state are never logged.

Tests:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
SIDELOAD_ADI_LIBRARY_DIR=/path/to/extracted/x86_64 cargo test native_adi_initialization_smoke -- --ignored
```

The deterministic ELF fixture executes a tiny function and checks its relative relocation;
malformed headers and unsupported relocations are rejected. Mock provisioning tests verify
stable identity, one-time provisioning, fresh OTPs, and cleanup after a failed exchange.

### Live validation

`tests/local_adi_live.rs` initializes the backend, provisions with Apple, requests two OTPs
back to back, waits 35 seconds (past the ~30 s OTP window) and checks that the OTP changed.
It uses temporary state, sends no Apple ID or password, and prints no generated header values.
Run it locally with `SIDELOAD_ADI_LIBRARY_DIR=/path/to/extracted/<abi> cargo test --test
local_adi_live -- --ignored --nocapture` (macOS needs no library directory), or on GitHub with
the manual **Live Anisette** workflow (`.github/workflows/live-anisette.yml`), which extracts
the libraries from Apple's APK itself.

Results on 2026-11-08 (GitHub-hosted runners): **passed** on Linux x86_64, Linux aarch64
(`ubuntu-22.04-arm`), Windows x64 and macOS arm64 (AOSKit, not signed into iCloud).
Back-to-back OTPs are identical within one window, so only the later request must differ.

An earlier attempt from a sandboxed environment (2026-11-07) failed with HTTP 503 from the
sandbox's proxy before reaching Apple; that was a network restriction, not a rejection.

A real Apple ID login (GSA SRP, 2FA, Xcode token, `team list`) succeeded on a Mac with 0.1.4
(2026-11-08), using the default local backend. Logging in with headers from the Android ADI
backends (Linux, Windows) has not been tried yet.

Not covered: Apple ID login with the Android ADI backends, macOS Intel, 16 KiB-page ARM kernels (large-page load shifting), a Mac signed into iCloud,
and ADI resynchronization.


## 10. macOS and Windows implementations

macOS uses the OS's AOSKit and AuthKit frameworks through the Objective-C runtime. It requests
OTP headers for DSID -2, and reads the device identity/client information from AKDevice. This
avoids Android ELF loading, bionic TLS, executable memory and foreign ARM64 ABI requirements on
Apple Silicon. Frameworks stay resident once loaded; each request uses an autorelease pool.
Missing classes/selectors, nil results, wrong value types and invalid OTP encoding fail with
`anisette_unavailable`; generated values are never logged. Private framework APIs can change
across macOS versions, and a machine's native Apple services may need provisioning/sign-in.

Windows x64 uses the ELF loader with VirtualAlloc/VirtualProtect/VirtualFree and explicit
instruction-cache flushing. All ADI entry points and callbacks use `extern "sysv64"`. CRT
adapters cross into the Windows ABI; passing CRT addresses directly to Android would corrupt
arguments/registers. The adapters convert UTF-8 paths to UTF-16, Android open flags to binary
CRT flags, CRT errors to Android errno, and stat64 into the 144-byte Linux x86_64 stat layout.
The layout and UTF-8 file I/O have Windows-specific tests. Android thread creation is still
unsupported and pthread objects remain confined to the serialized compatibility layer.

A deterministic test crosses System V and Win64 ABIs with eight arguments, checking both
register and stack arguments. The existing Linux official-library initialization smoke test
continues to pass. CI executes deterministic local-Anisette tests on its Linux ARM, macOS and
Windows runners; the optional native-library/live-service tests are never enabled by default.
Cross-compilation verifies Rust/platform types and C dependencies, not private framework
availability, native DLL linkage, or successful live OTP generation.
