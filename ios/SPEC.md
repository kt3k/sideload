# On-Device Refresher Specification

Status: Draft v2 (language-agnostic; on-device Anisette implementation in progress)

Purpose: Define an iOS application that signs IPA files with a free or paid Apple developer
account, installs them onto the same device it runs on, and keeps them working by refreshing
their provisioning profiles before they expire, without a computer after the initial setup.

This document builds on the Sideload CLI specification ([../SPEC.md](../SPEC.md), "the CLI
spec"). Sections of the CLI spec are cited as `CLI <section>`. Where this document does not say
otherwise, the rules of the cited CLI sections apply unchanged.

## Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY`, and
`OPTIONAL` are to be interpreted as described in RFC 2119. `Implementation-defined` means the
implementation chooses and documents the behavior.

`<App>` denotes the application this document specifies. Its name, bundle identifier, and icon
are Implementation-defined. The reference implementation is called `Sideload` (Section 13).

## 1. Problem Statement

Apps installed with a free Apple developer account stop launching when their provisioning profile
expires, 7 days after it was issued. Keeping them working with the CLI requires connecting the
device to a computer at least once a week.

`<App>` removes that requirement. It runs on the device and talks to the device's own lockdownd
through a loopback VPN, so that it can:

- sign an IPA the user downloaded and install it (the CLI `install` pipeline, run on the device);
- refresh installed apps: obtain new provisioning profiles and install them, which extends the
  apps' lifetime without reinstalling them;
- do the refresh on a schedule, unattended.

Important boundary: like the CLI, `<App>` manages only devices, development certificates, App IDs,
App Groups, and provisioning profiles on the Apple side, and only provisioning profiles and apps it
installed on the device.

## 2. Goals and Non-Goals

### 2.1 Goals

- Install a user-provided IPA onto the device `<App>` runs on.
- Refresh the apps it manages, and itself, before their profiles expire.
- Run refreshes without user interaction: from an automation the user sets up, and
  opportunistically in the background.
- Warn the user before an app expires when no refresh succeeded.
- Generate Anisette on the device without a third-party server (Section 4.4).
- Reuse the CLI's protocol, signing, and bundle code; the behavior of every Apple-side operation
  is the CLI's.

### 2.2 Non-Goals

- An app catalog, sources, update feeds, or downloading apps by itself.
- JIT enabling, app data backup, app icon or name customization, extension removal.
- Pairing the device by itself. The pairing file is created on a computer (Section 5.1).
- RemotePairing (the iOS 17+ CoreDevice tunnel) and RSD services. Only the lockdown protocol over
  TCP is used (Section 12).
- Managing apps it did not install, other than itself.
- Installing onto any device other than the one it runs on.

## 3. System Overview

### 3.1 Main Components

1. `User Interface`: shows the managed apps and their expiry, runs install and refresh on
   demand, collects settings, credentials, and 2FA codes.
2. `Secure Store`: the OS keychain. Holds the password and the saved session (Section 4.2).
3. `Scheduler`: entry points that start a refresh without user interaction (Section 8).
4. `Core`: everything below the interface: the operations of Section 7, the registry
   (Section 4.5), the Anisette provider, the Developer Service Client, the Device Client, the
   Bundle Processor and the Code Signer of the CLI spec (CLI 3.1).
5. `Core Interface`: the boundary between the User Interface / Scheduler and the Core
   (Section 9).

### 3.2 External Dependencies

- Apple authentication servers and the Developer Services API (HTTPS), as in CLI 3.3.
- An on-device Anisette engine, or an explicitly configured anisette-v3 server (Section 4.4).
- A loopback VPN app that routes a tunnel peer address back to the device itself, such as
  LocalDevVPN. `<App>` does not ship a VPN.
- A pairing file created on a computer (Section 5.1).

### 3.3 Device Link

The Device Client of the CLI reaches lockdownd through usbmuxd. `<App>` instead opens TCP
connections to the device's own address on the loopback VPN:

- `device_host`: the tunnel peer address. Default `10.7.0.1`; configurable.
- lockdownd: `device_host:62078`. Services started with `StartService`: `device_host:<port>`.
- Session setup, TLS, and the services follow CLI 10.3, using the pairing file instead of the
  usbmuxd pair record.
- Connecting MUST time out (the reference implementation uses 5 seconds) and reads and writes
  SHOULD time out, so that an unavailable VPN fails quickly instead of stalling a background run.
- A failure to connect MUST be reported as `device_transport_error` with a message that names
  `device_host` and asks the user to turn the VPN on.

## 4. Core Domain Model

### 4.1 Data Directory

All files the Core persists live in one directory inside the app's sandbox, chosen by the User
Interface and passed on every call (Section 9). It MUST be excluded from backups.

Layout:

- `keys/<key_id>/key.pem`: the signing key, as CLI 4.1.1 and CLI 4.2. This key is generated on
  the device and is distinct from any computer's key.
- separate on-device and remote anisette-v3 state (Section 4.4).
- `pairing.plist`: the pairing file (Section 4.3).
- `apps.json`: the registry (Section 4.5).
- `apps/<bundle_id>/app.ipa`: the original IPA of each managed app (Section 4.5).

Files that hold secrets (`keys/`, `pairing.plist`) MUST be created with file protection that
keeps them unreadable before the first unlock after boot, and readable afterwards, so that
background runs work while the device is locked.

### 4.2 Account

- `apple_id`: lowercased before use (CLI 4.1.2).
- `password`: unlike the CLI (CLI 2.2), `<App>` stores the password, because unattended refresh
  must be able to log in again. It MUST be stored only in the Secure Store, as a device-only item
  readable after the first unlock. It MUST NOT be written to the data directory or logged.
- `session`: the Developer Services session (adsid, token, expiry; CLI 9.6). The Core returns a
  new session after every login; the User Interface stores it in the Secure Store and passes it
  back on later calls. The reuse rules of CLI 9.6 apply (valid for at least 10 more minutes,
  verified with `list_teams()`, otherwise discarded and replaced by a normal login).
- `team_id`: OPTIONAL. Team selection follows CLI 9.3.
- A 2FA code is obtained from the user interactively (CLI 9.2 step 5, including `resend`). In an
  unattended run no code can be obtained, and the run MUST fail with `two_factor_failed` instead of
  waiting.

### 4.3 Pairing File

A lockdown pairing record for the device, in the format of the usbmuxd pair record (XML or binary
plist with `HostCertificate`, `HostPrivateKey`, `HostID`, `SystemBUID`, and optionally `UDID`,
`DeviceCertificate`, `EscrowBag`). It is parsed as the CLI parses pair records.

- Importing MUST validate the file and replace `pairing.plist` only if it is valid. An invalid
  file fails with `device_not_paired`.
- The pairing file grants full lockdown access to the device. It MUST NOT be logged or sent
  anywhere other than the device's lockdownd.

### 4.4 Anisette

The target is on-device generation by default, with an explicit remote option. The project
remains MIT-licensed: the interpreter MUST be implemented independently from the AArch64
architecture and ELF ABI, without incorporating GPL/AGPL emulator code. AnisetteKit and Unicorn
are not dependencies. The staged implementation and remaining work are tracked in
[ANISETTE.md](ANISETTE.md) (on-device generation is not yet available in the app).

Backend selection at the Core Interface is explicit when `anisette_mode` is supplied:

- `"local"` selects the in-process Rust interpreter and ignores any saved remote URL. Acquire
  the official AArch64 libraries regardless of the host CPU, and reuse the CLI provisioning
  protocol through the interpreted `Engine`. No Swift header callback is required.
- `"remote"` requires a non-empty `anisette_server` URL. Validate its `http`/`https` URL as in
  CLI 5.6; a missing URL fails during `PreparingAnisette` with `anisette_unavailable`.
- Missing/null/empty `anisette_mode` preserves the earlier interface: a non-empty server URL
  selects remote-v3; otherwise the scoped host callback is required. A missing callback fails
  before password or 2FA interaction. Unknown modes/types fail with `invalid_arguments`.

The app defaults to Remote Server while the local backend is experimental, preserving existing
settings. It MAY expose `On Device (Experimental)` as an explicit opt-in. Local failures MUST
NEVER silently use a public server. Local mode MUST NOT become the default or be described as
stable before successful Apple provisioning/OTP validation and real-device validation.

The on-device engine MUST interpret the Android AArch64 ADI libraries as guest data. It MUST
NOT use JIT, host executable mappings, private Apple frameworks, a debugger entitlement, or a
localhost HTTP server. Guest memory, imported functions and instruction execution MUST be
bounded; unsupported instructions/imports MUST fail closed. Proprietary ADI libraries MUST NOT
be bundled in the app; acquire them from Apple's official distribution when the user enables
local generation. Download and provisioning may need a foreground run and network access to
Apple; on-device generation does not mean offline provisioning.

Local identity, provisioning blobs and libraries belong under a separate `data_dir/anisette-local`
directory with the same protection and backup exclusions as Section 4.1. Do not reuse remote
server state as local provisioning. Failed downloads or provisioning MUST NOT overwrite valid
state. Guest files are read and written in a private staging copy of the provisioning
directory; copy validated files back atomically per file only after successful header generation.
The guest sees virtual `/adi` paths and MUST NOT access files outside this directory.
Resetting identity/provisioning requires an explicit user action.

The interpreted provider generates headers directly in Rust. For hosts using the optional
callback bridge instead, the host returns fresh headers through `anisette_headers` on the
core worker thread; it MUST NOT cache and reuse an OTP across header requests. The callback
returns a malloc-allocated UTF-8 JSON object `{"headers":{...}}` or NULL on failure. The core
frees it, accepts at most 64 KiB, and validates header names, values and required fields before
use. The required fields are `X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`,
`X-Apple-I-MD-LU`, `X-Mme-Device-Id`, `X-Mme-Client-Info`, `X-Apple-I-Client-Time`,
`X-Apple-I-TimeZone`, and `X-Apple-Locale`; optional fields are `User-Agent` and
`X-Apple-I-SRL-NO`. Duplicate names (case-insensitive), unknown names, empty values, control
characters and values above 8 KiB MUST be rejected. Callback context is valid only during the
core call and MUST NOT be retained or used to reenter `sideload_call`.

Passwords and 2FA codes MUST NOT be passed to the engine. OTPs, machine IDs, provisioning blobs
and raw engine responses MUST NOT appear in logs or errors. Remote mode remains opt-in: the UI
MUST label its server as a third party. The UI MUST label local mode as experimental during validation. `Check Anisette` calls
`prepare_anisette` without credentials and reports success only after headers are actually
generated. The existing remote configuration remains usable during implementation.

### 4.5 Managed App Record

The registry `apps.json` holds one record per managed app:

- `bundle_id` (string): the installed main bundle identifier (after CLI 4.2 rewriting). Primary
  key.
- `original_bundle_id` (string): the identifier before rewriting.
- `name` (string), `version` (string or null): from the main bundle's `Info.plist`.
- `team_id` (string): the team the app was signed for.
- `bundles` (list of `{bundle_id, name}`): the main bundle and every extension that was signed,
  with the bundle name used for its App ID name (CLI 4.2).
- `certificate_sha256` (hex string or null): SHA-256 of the DER certificate the app was signed
  with. Null when unknown (Section 4.6).
- `profile_expires` (Unix seconds or null): the earliest `ExpirationDate` among the profiles last
  installed for the app.
- `installed_at`, `refreshed_at` (Unix seconds or null).
- `source`: `ipa` (installed by `<App>`, the original IPA is kept) or `self` (Section 4.6).

Rules:

- The registry MUST be written atomically (write a temporary file, then rename).
- Unknown fields MUST be ignored when reading, so that later versions can add fields.
- A missing registry is an empty registry. An unreadable or malformed registry MUST fail with
  `internal_error` rather than be overwritten.
- The original IPA is kept so that an app can be re-signed when profile-only refresh is not
  possible (Section 7.4). It is deleted together with its record (Section 7.5).

### 4.6 The App Itself

`<App>` is installed by another tool (normally the CLI), so it has no IPA and its signing
certificate is not known to the Core. The User Interface passes the path of `<App>`'s own bundle on
every call. The Core derives a `self` record from it:

- `bundle_id`, `name`, `version`: from the bundle's `Info.plist`.
- `team_id` and the initial `profile_expires`: from the bundle's `embedded.mobileprovision`
  (`TeamIdentifier[0]`, `ExpirationDate`).
- `bundles`: the main bundle and the extensions found as in CLI 4.1.10.
- `certificate_sha256`: null.

The record is stored in the registry the first time it is refreshed, so that later expiry dates
come from the registry. `profile_expires` is the later of the stored value and the embedded
profile's. The `self` record MUST NOT be removed by Section 7.5.

## 5. Setup

### 5.1 Prerequisites

1. Install `<App>` with the CLI (`sideload install -l` downloads and installs the reference
   implementation, CLI 7.8; `sideload install <App>.ipa` installs a local copy) or any other
   sideloading tool.
2. Put the pairing file of a computer the device trusts into `<App>`. The CLI does this when it
   installs the reference implementation, and with `sideload sidestore pairing-file`
   (CLI 10.4): it writes the usbmuxd pair record, with `UDID` added, to `<App>`'s
   `Documents/ALTPairingFile.mobiledevicepairing`. A pairing file made by another tool can be
   imported from Files or the share sheet instead.
3. Install and turn on the loopback VPN.
4. Enter the Apple ID and password in `<App>`, and select an available Anisette backend
   (Section 4.4). During local engine development, configure a remote server explicitly.

Before every operation that connects to the device, `<App>` imports
`Documents/ALTPairingFile.mobiledevicepairing` if it exists (Section 4.3) and deletes it after a
successful import, so a newer file from the computer takes effect without user action.

### 5.2 Setup Checks

The User Interface MUST provide a connection check (Section 7.1) that reports, in order, the first
of: no pairing file, VPN not reachable, pairing rejected, or success with the device's name, UDID,
and iOS version.

## 6. Phases

Install and refresh report progress with the phase names of CLI 7.2 where a phase applies, plus:

- `ConnectingDevice`: open lockdownd over the Device Link (Section 3.3) and read the device's UDID
  and name. It replaces CLI `SelectingDevice`.
- `RefreshingApp`: one per managed app during refresh (Section 7.4).
- `InstallingProfiles`: install profiles through misagent without reinstalling the app.

Errors use the codes of CLI 13.1 and carry the phase where it is known.

## 7. Operations

### 7.1 Connect

1. Read `pairing.plist`. If it is missing, fail with `device_not_paired` ("import a pairing
   file").
2. Connect to lockdownd at `device_host:62078` (Section 3.3), `QueryType`, `StartSession` with the
   pairing record.
3. Read `UniqueDeviceID`, `DeviceName`, and `ProductVersion`.
4. If the pairing file contains `UDID` and it differs from `UniqueDeviceID`, fail with
   `device_not_paired` (the file is for another device).

The device's UDID is always taken from lockdownd, never only from the pairing file.

### 7.2 Log In

CLI 9.2 to 9.4 with the account of Section 4.2:

1. Prepare the selected Anisette provider (`PreparingAnisette`, Section 4.4).
2. If a session is given and usable, verify it with `list_teams()`; use it if that succeeds.
3. Otherwise authenticate with `apple_id` and `password`; ask for a 2FA code through the Core
   Interface when Apple requires one.
4. Select the team (CLI 9.3).
5. Return the session if a new one was created, so the User Interface can store it.

### 7.3 Install

Input: the path of an IPA. Phases in order:

1. `PreparingBundle`: extract the IPA into a fresh working directory, load the bundle, and check
   extension identifiers (CLI 11.1, CLI 4.2). No `--strip-extensions`, `--name`, or `--bundle-id`
   equivalents are offered.
2. `ConnectingDevice`: Section 7.1. Local and device failures are reported before logging in, as
   in CLI 7.2.
3. `PreparingAnisette`, `LoggingIn`, `SelectingTeam`: Section 7.2.
4. `Planning`: compute the Main Bundle ID (CLI 4.2, without override), rewrite identifiers, and
   check the App ID quota (CLI 7.4). If a record with the same `bundle_id` exists, this is a
   reinstall of that app.
5. `RegisteringDevice`: register the device if its UDID is not registered (CLI 10.2).
6. `PreparingCertificate`: CLI 7.3 without `--new-cert`. `<App>` MUST NOT revoke certificates.
7. `RegisteringAppIds`, `ConfiguringAppGroup`, `FetchingProfiles`: as in CLI 7.2, including the
   SideStore tweak of CLI 11.1.
8. `Signing`: CLI 11.2.
9. `Delivering`: CLI 10.3 over the Device Link.
10. `CleaningUp`: copy the original IPA to `apps/<bundle_id>/app.ipa`, write the record
    (`certificate_sha256` = the signing certificate, `profile_expires` from the profiles,
    `installed_at` = now, `source = ipa`), and delete the working directory.

The record is written only after a successful delivery. Re-running a failed install MUST be able
to continue (CLI 7.6).

### 7.4 Refresh

Input: an optional list of bundle identifiers (default: every record, including `self`), and an
optional threshold `within` (seconds). With `within`, only apps whose `profile_expires` is null or
earlier than `now + within` are refreshed; if none qualifies, the operation succeeds without
connecting or logging in.

1. `ConnectingDevice` (Section 7.1).
2. `PreparingAnisette`, `LoggingIn`, `SelectingTeam` (Section 7.2), once for the whole run.
3. `RegisteringDevice`: register the device if needed (CLI 10.2), once.
4. For each selected app, in registry order, `RefreshingApp`:
   1. If the record's `team_id` differs from the selected team, fail this app with
      `team_not_found`.
   2. `RegisteringAppIds`, `ConfiguringAppGroup`, `FetchingProfiles` for the record's `bundles`,
      exactly as install does. App IDs that expired are registered again (counting against the
      quota, CLI 7.4).
   3. Profile-only refresh is possible when `certificate_sha256` is null, or when every fetched
      profile's `DeveloperCertificates` contains a certificate with that SHA-256.
      - If possible, `InstallingProfiles`: install every profile through misagent.
      - Otherwise, if `source = ipa`, re-sign: run Section 7.3 steps 1 and 6 to 9 on the stored
        IPA with the record's `bundle_id` as the Main Bundle ID, and update
        `certificate_sha256`.
      - Otherwise fail this app with `signing_failed` ("reinstall `<App>` from a computer").
   4. Update `profile_expires` and `refreshed_at`, and write the registry.
5. The operation succeeds if every selected app succeeded. Otherwise it fails with the first
   app's error, and the result still lists the outcome of every app.

A failure of one app MUST NOT stop the refresh of the others, except for failures of steps 1 to 3,
which stop the run.

The signing certificate (CLI 7.3) is prepared only when a re-sign is needed, so that a run of
profile-only refreshes never creates a certificate.

### 7.5 Forget

Input: a bundle identifier. Removes the record and its stored IPA. It does not uninstall the app
and changes nothing on the Apple side. An unknown identifier, or the `self` record, fails with
`invalid_arguments`.

### 7.6 List

Returns every record, the `self` record included, ordered with `self` first and then by `name`.
It neither connects nor logs in.

## 8. Scheduling

The refresh threshold for unattended runs is Implementation-defined; 2 days is RECOMMENDED, which
leaves several chances to succeed before a 7-day profile expires.

1. On demand: the User Interface offers "refresh all" and per-app refresh, without a threshold.
2. Automation: `<App>` MUST expose refresh as a system action the user can run from an automation
   (on iOS, an App Intent usable from Shortcuts), so that the user can schedule it (for example
   daily, or when the device starts charging). It runs with the threshold, without opening the
   User Interface, and reports the outcome as text.
3. Background: `<App>` SHOULD request opportunistic background execution and run a refresh with
   the threshold when the system grants it. The system decides when and whether this happens.
4. Notification: after every refresh and at launch, `<App>` SHOULD schedule a local notification
   one day before the earliest `profile_expires`, replacing any earlier one, so that the user can
   act when unattended refreshes keep failing.

Unattended runs never ask for input (Section 4.2) and never start an install. When two runs
overlap, the second MUST wait for the first or fail; operations on the Core are serialized.

## 9. Core Interface

The User Interface and the Core communicate through one call that takes a request and returns a
response, both JSON objects. The reference implementation exposes it as a C function (Section 13).

### 9.1 Request

```json
{
  "op": "install | refresh | apps | forget | connect | import_pairing | login | prepare_anisette | version",
  "config": {
    "data_dir": "<path>",
    "anisette_mode": "<local | remote | null (legacy selection)>",
    "anisette_server": "<url or null>",
    "device_host": "<host or null (default 10.7.0.1)>",
    "self_bundle": "<path of <App>'s own .app or null>"
  },
  "account": {
    "apple_id": "<string>",
    "password": "<string or null>",
    "session": "<opaque string or null>",
    "team_id": "<string or null>"
  },
  "args": { }
}
```

`account` is required only by operations that log in (`install`, `refresh`, `login`). `args` per
operation:

- `install`: `{"ipa": "<path>"}`
- `refresh`: `{"bundle_ids": ["..."] or null, "within": <seconds> or null}`
- `forget`: `{"bundle_id": "..."}`
- `import_pairing`: `{"path": "<path>"}`
- others: `{}`

### 9.2 Response

Success: `{"ok": true, "result": {...}, "session": "<new session or absent>"}`.
Failure: `{"ok": false, "error": {"code": "<CLI 13.1 code>", "phase": "<phase or null>",
"message": "..."}, "result": {...} or absent}`.

Results:

- `version`: `{"version": "<semver>"}`
- `prepare_anisette`: `{"ready": true}` only after header generation; no account or secret
  values are returned. Runs acquisition/provisioning when needed in local mode.
- `connect`: `{"udid", "name", "product_version"}`
- `import_pairing`: `{"udid": "<from the file, or null>"}`
- `login`: `{"teams": [{"team_id", "name"}]}`
- `install`: `{"app": <record>}`
- `refresh`: `{"apps": [{"bundle_id", "ok", "action": "profiles | resign | skipped", "error"}]}`
- `apps`: `{"apps": [<record>]}`
- `forget`: `{}`

Records are the fields of Section 4.5.

### 9.3 Callbacks

A call receives two callbacks from the caller:

- `log(level, message)`: progress and log lines (levels: debug, info, warn, phase). Messages MUST
  NOT contain secrets (CLI 14.2).
- `two_factor_code() -> string or none`: blocks until the user enters a code or `resend`; none
  cancels the login (`two_factor_failed`). Unattended callers return none immediately.

Calls block until done and are serialized (Section 8).

## 10. User Interface

The User Interface MUST provide:

- the list of managed apps with name, version, and time left until `profile_expires`, with
  refresh and forget actions;
- import of an IPA (file picker and "open in"), which starts an install;
- settings: Apple ID, password, team (optional), Anisette backend and remote server (optional), device host, pairing file
  import, connection check;
- a 2FA code prompt with a way to request a new code;
- the log of the last operation, with the error code and phase of a failure.

It SHOULD keep the screen awake while an install or refresh started from the User Interface runs.

## 11. Security

- CLI 14 applies. Secrets are the password, the session, the signing key, and the pairing file.
- The password and session live only in the Secure Store (Section 4.2); the key and the pairing
  file only in the data directory with the protection of Section 4.1.
- Logging out removes the password and session from the Secure Store. Removing the signing key is
  not offered (it is the only key matching the device's certificate).
- IPAs are user-supplied. `<App>` signs them with the user's certificate; it MUST NOT download
  apps by itself (Section 2.2).

## 12. Known Limitations

- Apps signed with a revoked or expired certificate stop launching, including `<App>`. Revoking
  all Sideloader certificates from a computer (`sideload install --new-cert`) disables `<App>`
  until it is reinstalled.
- Free accounts allow 3 active sideloaded apps per device, including `<App>`, and 10 new App IDs
  per 7 days (CLI 13.1).
- On iOS 26.4 and later, lockdown over a loopback VPN needs a VPN that provides the interface the
  system requires (LocalDevVPN documents this); otherwise the connection check fails and only
  RemotePairing (a non-goal) would work.
- The system limits background execution; scheduled refresh depends on the user's automation and
  on the system granting background time.

## 13. Reference Implementation

- Name `Sideload`, original bundle identifier `io.github.kt3k.sideload`, minimum iOS 16.
- `ios/core/`: the Core and the Core Interface in Rust, a static library on top of the `sideload`
  crate. The C interface is `ios/core/include/sideload_core.h`:
  `char *sideload_call(const char *request_json, SideloadCallbacks callbacks)` and
  `void sideload_string_free(char *)`.
- `ios/Sideload/`: the User Interface, Secure Store, and Scheduler in Swift (SwiftUI, App Intents,
  BackgroundTasks, UserNotifications).
- `ios/project.yml`: the Xcode project, generated with XcodeGen. The CI workflow
  `.github/workflows/ios.yml` builds an unsigned `Sideload.ipa` and, on pushes to `main`,
  publishes it to the `sideload-app` pre-release, from which `sideload install -l` installs it.
- Unattended refresh threshold: 2 days. Background task identifier:
  `io.github.kt3k.sideload.refresh`, fixed rather than derived from the bundle identifier,
  because sideloading tools rewrite `CFBundleIdentifier` but not
  `BGTaskSchedulerPermittedIdentifiers`.
- On-device Anisette is experimental: scalar/integer SIMD instructions, guest ELF linking,
  Android runtime shims, interpreted `Engine`, provisioning staging and Settings integration
  are implemented. Official-library initialization, the unprovisioned query and invalid-input
  rejection pass on a Linux x86_64 host interpreting AArch64. Successful Apple provisioning,
  OTP generation/rotation and iOS device login/refresh remain unverified. See
  [ANISETTE.md](ANISETTE.md).
- The anisette server has no default; the settings screen offers SideStore's public server
  (`https://ani.sidestore.io`) as a one-tap suggestion, labeled as a third party.
- Build: `ios/build-core.sh` (static library, Cargo profile `ios`), then
  `cd ios && xcodegen generate`, then Xcode or `xcodebuild`.

## 14. Test and Validation Matrix

Deterministic (unit tests with mocks):

- Registry: round trip, atomic write, unknown fields ignored, malformed file rejected, ordering of
  List, Forget of unknown and `self`.
- `self` record derivation from a bundle with an embedded profile.
- Refresh selection with and without `within`; the profile certificate check; the choice between
  profile-only, re-sign, and failure.
- Pairing import: valid file replaces, invalid file leaves the old one.
- Anisette bridge: fresh callback per request, scope cleanup including unwinding, missing
  callback, malformed/duplicate/injected headers, generic errors without OTP disclosure.
- Interpreter: independently assembled AArch64 programs, register width and NZCV, call/return
  and stack, memory permissions/bounds, instruction budget, unsupported opcode traps.
- Core Interface: request parsing errors map to `invalid_arguments`; responses for success and
  failure; `version`, `apps`, and `forget` without network.

Real integration (RECOMMENDED before release):

- Connection check with the VPN on and off.
- Install of a small IPA, then a refresh that only installs profiles and extends the expiry.
- A refresh from the Shortcuts automation while the device is locked.
- Local Anisette: first-run acquisition, Apple provisioning, fresh OTP requests and rotation after an OTP time window,
  real account login, relaunch with saved state, and locked-device refresh without a remote URL.
  This validation is pending; interpreter unit tests alone do not establish ADI compatibility.

## 15. Definition of Done

- Every operation of Section 7 is implemented through the Core Interface.
- The User Interface of Section 10 and the scheduling entry points 1, 2, and 4 of Section 8 are
  implemented; entry point 3 is RECOMMENDED.
- The deterministic tests of Section 14 pass, and the iOS app builds in CI.
