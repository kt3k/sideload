# On-device Anisette implementation

The target contract is [SPEC.md Section 4.4](SPEC.md#44-anisette). The project retains its MIT
license. The implementation uses our own AArch64 interpreter and ELF loader; it does not depend
on AnisetteKit, Unicorn, QEMU, JIT or Apple's private iOS frameworks. Architecture references:
[Arm A-profile architecture](https://developer.arm.com/documentation/ddi0487/latest/) and
[AArch64 ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst).
No external emulator implementation has been copied into this code.

**Current status: foundation implemented; real ADI and serverless iOS login do not work yet.**
The shipped Settings screen still requires an explicit remote server. Interpreter tests are not
evidence of ADI compatibility. Do not enable a local-mode picker until stage 4 below passes.

## Implemented

- `core/src/emulation.rs`: guest memory with bounded allocations (128 MiB total), access
  permissions, checked ranges and no conversion of guest addresses to host pointers. Guest
  executable permission controls interpreter fetch only; no host memory is executable.
- Scalar AArch64 subset: NOP; B/BL, BR/BLR/RET; conditional, compare and test branches;
  ADR/ADRP; MOVN/MOVZ/MOVK; immediate and shifted-register ADD/SUB with NZCV;
  shifted-register logical operations; unsigned-immediate integer LDR/STR. Registers support
  XZR/WZR and SP where defined, and W writes clear the upper half.
- `core/src/emulation/elf.rs`: guest-only ELF64 loading using the existing in-tree parser,
  zeroed BSS, exported symbols, explicit import addresses, and AArch64 RELATIVE, ABS64,
  GLOB_DAT and JUMP_SLOT relocations. Unknown strong imports/relocations fail. ELF constructors
  are not executed. There is no Android runtime or multi-library linking coordinator yet.
- Finite per-run instruction budget. Unsupported instructions and invalid memory access trap.
  No guest SVC or system-register instruction dispatches to the host operating system.
- `core/src/anisette.rs`: a call-scoped host header provider, called afresh per header request.
  Returned JSON has a 64 KiB acceptance limit and a strict header allowlist, required fields,
  duplicate/control-character rejection and generic errors that exclude response contents.
- C ABI + Swift callback plumbing (`anisette_headers`). The callback returns a malloc-allocated
  NUL-terminated JSON string, or NULL; Rust frees it. The context is scoped to `sideload_call`,
  restored on unwinding, and unavailable outside that worker-thread call. This changes the C
  callback struct: rebuild the Swift app and Rust static library together.
- Core selection: an explicit `anisette_server` retains remote-v3 behavior. Without one the
  host callback is required, and a missing callback fails during `PreparingAnisette`. There is
  no public-server fallback. No real engine is attached to this callback yet.

Tests cover assembled arithmetic loops and stack/call programs, register width/flags, guest
memory protections, instruction budget and unsupported opcode traps, ELF relocation followed
by interpreting a guest entry point, and callback freshness/validation/lifetime.
`core/tests/fixtures/aarch64.S` contains the independent assembly inputs checked with LLVM's
assembler through Zig. Reproduce assembly with:

```sh
zig cc -target aarch64-linux-gnu -c ios/core/tests/fixtures/aarch64.S -o /tmp/aarch64.o
cargo test -p sideload-ios-core
```

The macOS iOS workflow runs the Rust tests and builds the unsigned Swift app. Linux tests do
not validate iOS code signing, background execution, provisioning or Apple's acceptance of OTPs.

## Remaining stages

1. **ADI instruction/runtime coverage.** Run the official Android AArch64 libraries as guest
   data. Extend the interpreter for the integer, bitfield, multiply/divide, load/store and SIMD
   instructions actually encountered. Build independent assembler fixtures and reference
   results for each addition. Add guest TLS and a bounded import dispatch table for Android
   memory, files, clocks, randomness, synchronization and loader calls. Guest strings/buffers
   must be checked and copied; never cast guest pointers to host addresses. Imported file
   operations must remain inside the private local-state directory. Cross-library relocation,
   initialization order and ABI marshalling must be handled explicitly. Unsupported imports
   must not call the native CLI hooks.
2. **Provisioning Engine.** Implement the existing
   `sideload::anisette::local_adi::provisioning::Engine` over interpreted ADI entry points,
   then reuse the existing identity, Apple provisioning exchange and header formatting.
   Preserve cleanup/destroy behavior on every failure. Keep instruction/time/memory budgets
   finite and report errors without ADI buffers or provisioning data.
3. **Acquisition, storage and UI.** Reuse official Apple library acquisition, select AArch64
   independently of the host architecture, and place all local state under
   `data_dir/anisette-local`. Ensure atomic installation, file protection, exclusion from
   backups and separation from saved remote state. Wire the real provider into the callback,
   add foreground preparation and explicit local/remote selection, preserve existing remote
   users, and provide explicit reset/retry. Do not offer automatic third-party fallback.
4. **Real iOS validation.** On an ordinary sideloaded device without JIT/debug entitlements:
   acquire libraries, provision with Apple, generate distinct OTPs, log in with a real account,
   relaunch with persisted state, install/refresh an app and refresh from Shortcuts while
   locked. Check failure/retry after interrupted acquisition and offline provisioning. Only
   then label local generation as available and make it the default for new users.

No proprietary ADI library is checked into the repository or included in app artifacts by this
change. A successful synthetic ELF test must not be reported as real Anisette generation.
