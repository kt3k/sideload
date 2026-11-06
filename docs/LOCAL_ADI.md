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
| macOS arm64 | `arm64-v8a` | same as macOS x86_64 | built in CI; whether it runs reliably (Darwin arm64 ABI and memory-protection differences) is unverified |

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
  `<config>`) so that a machine provisioned by Sideloader is reused as-is.
