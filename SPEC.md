# Sideload CLI Specification

Status: Draft v2 (language-agnostic)

Purpose: Define a command-line tool that sideloads an iOS application package (IPA) onto a
connected device using a free or paid Apple developer account, plus the minimum set of
diagnostic commands needed when that installation fails.

Upstream reference: [Dadoum/Sideloader](https://github.com/Dadoum/Sideloader) `frontends/cli`
(commit `ed89e28`). This specification is a reduced, corrected subset of that CLI.

## Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY`, and
`OPTIONAL` in this document are to be interpreted as described in RFC 2119.

`Implementation-defined` means the behavior is part of the implementation contract, but this
specification does not prescribe one universal policy. Implementations MUST document the selected
behavior.

## 1. Problem Statement

Sideload CLI is a command-line tool that installs an IPA file onto a USB-connected iOS device using
an Apple developer account (including free accounts).

The tool solves three problems:

- It performs the whole chain — device registration, certificate preparation, App ID registration,
  provisioning profile retrieval, signing, transfer, and installation — in a single command, without
  Xcode or macOS.
- It reports failures caused by the strict limits of free accounts (10 App IDs per 7 days, a cap on
  certificates, etc.) in a way that identifies the cause, and gives users the means to resolve them
  on their own.
- It drops the upstream Sideloader CLI features that are not needed for installation and fixes
  known upstream defects.

Important boundary:

- The only Apple-side resources the tool manages are devices, development certificates, App IDs,
  App Groups, and provisioning profiles.
- The tool changes Apple-side state as a side effect (for example, registering App IDs). Some of
  these changes do not restore quota when undone (Section 13.4). `--dry-run` is provided to preview
  the outcome without making changes.

## 2. Goals and Non-Goals

### 2.1 Goals

- Install an IPA onto a device with a single `install` command.
- On installation failure, report the cause as the failing phase plus an error code.
- Provide diagnostic commands to inspect and resolve the causes of failure (limits reached,
  inconsistent state).
- Accept credentials both interactively and through environment variables.
- Support both a local ADI and a remote Anisette server.
- Keep the layout of the configuration directory (keys, ADI state) compatible with upstream
  Sideloader, so its files can be copied over. The directory itself is separate (Section 6.3).

### 2.2 Non-Goals

- Upstream commands not needed for installation, such as `sign` (standalone signing),
  `trollsign`, and `tool` (SideStore pairing file). `device pairing-file` (Section 8.9) covers
  the pairing file needed by the on-device app.
- Persisting credentials (the password is never stored). Saving the login session is limited to
  the OS keyring as described in Section 9.6.
- Fully unattended login including 2FA. The user always enters the 2FA code.
- A GUI.
- Installation for platforms other than iOS (tvOS, standalone watchOS apps, macOS).
- Requiring device connection over Wi-Fi (support is Implementation-defined).

## 3. System Overview

### 3.1 Main Components

1. `CLI Front End`
   - Parses and validates command-line arguments.
   - Dispatches subcommands and determines the exit code.

2. `Config Layer`
   - Resolves typed configuration values from CLI options, environment variables, and defaults
     (Section 6).
   - Determines the location of the configuration directory.

3. `Credential Provider`
   - Obtains the Apple ID, password, and 2FA code from environment variables or interactive input
     (Section 9.2).

4. `Anisette Provider`
   - Produces the Anisette data required for Apple authentication.
   - Has two backends: local ADI (loads Android libraries) and a remote server.

5. `Developer Service Client`
   - Performs Apple authentication (GSA) and calls the Developer Services API.

6. `Device Client`
   - Enumerates connected devices through usbmuxd and talks to lockdown, AFC, installation_proxy,
     and misagent.

7. `Bundle Processor`
   - Extracts the IPA and rewrites bundle identifiers, the display name, and extensions.

8. `Code Signer`
   - Signs Mach-O binaries and bundles with a certificate, private key, and provisioning profile.

9. `Install Pipeline`
   - Combines the components above to perform installation following Section 7.

10. `Output / Logging`
    - Emits progress, listings, logs, and error reports.

### 3.2 Abstraction Levels

To keep the tool easy to port, implementations are RECOMMENDED to use these layers:

1. `Interface Layer`: CLI Front End, Output / Logging.
2. `Configuration Layer`: Config Layer, Credential Provider.
3. `Coordination Layer`: Install Pipeline and the diagnostic command handlers.
4. `Integration Layer`: Anisette Provider, Developer Service Client, Device Client.
5. `Artifact Layer`: Bundle Processor, Code Signer.

### 3.3 External Dependencies

- Apple authentication servers and the Developer Services API (HTTPS).
- When using local ADI: the ADI libraries (`libstoreservicescore.so`, `libCoreADI.so`) and network
  access for their initial download.
- When using remote Anisette: an anisette-v3 compatible server.
- usbmuxd (the usbmuxd daemon on Linux, built in on macOS, Apple Mobile Device Support on Windows).
- A local filesystem for the configuration directory and the working directory.
- When `install --sidestore` is used: the GitHub REST API (`api.github.com`) and GitHub release
  asset hosts (Section 7.7).

## 4. Core Domain Model

### 4.1 Entities

#### 4.1.1 Configuration Directory

Location of all data the tool persists. Its path is determined by Section 6.3.

Layout:

- `lib/libstoreservicescore.so`, `lib/libCoreADI.so`
  - Libraries for local ADI. Downloaded automatically when missing.
- ADI provisioning state under `lib/`
  - Implementation-defined. Compatibility with upstream is RECOMMENDED.
- `keys/<key_id>/key.pem`
  - The 2048-bit RSA private key used for signing (PEM, PKCS#8). `<key_id>` is defined in
    Section 4.2.

#### 4.1.2 Credentials

- `apple_id` (string)
  - REQUIRED. MUST be converted to lowercase before any use (the SRP username and the `Key ID`),
    as upstream does.
- `password` (string)
  - REQUIRED. MUST NOT be stored.
- `two_factor_code` (string or null)
  - Obtained only when Apple requests it.

#### 4.1.3 Team

- `team_id` (string): REQUIRED. The team ID issued by Apple.
- `name` (string)

#### 4.1.4 Registered Device

A device registered with the account.

- `device_id` (string): Apple-side identifier. Used as the argument to `device delete`.
- `udid` (string): The device UDID (`deviceNumber` upstream).
- `name` (string)

#### 4.1.5 Connected Device

A device currently visible through usbmuxd.

- `udid` (string)
- `name` (string or null): Device name obtained from lockdown.

#### 4.1.6 Development Certificate

- `serial_number` (string)
- `name` (string)
- `machine_name` (string)
  - For certificates created by this tool, this MUST be the constant `Sideloader`. This value is
    used regardless of the executable name, for compatibility with upstream.
- `certificate_id` (string)
- `content` (bytes): DER-encoded X.509 certificate.

#### 4.1.7 App ID

- `identifier` (string): Bundle identifier.
- `name` (string)
- `expiration_date` (timestamp)
- `features` (map): Includes whether App Groups are enabled.

Listing App IDs also returns `available_quantity` (remaining quota) and `max_quantity` (quota
limit). Either MAY be absent (paid teams have no App ID quota); absent means unlimited.

#### 4.1.8 App Group

- `identifier` (string): Starts with `group.`.
- `name` (string)

#### 4.1.9 Provisioning Profile

- `app_id` (string): The target App ID.
- `encoded_profile` (bytes): Contents of the `.mobileprovision` file.

#### 4.1.10 App Bundle

A `.app` extracted into the working directory.

- `bundle_identifier` (string): `CFBundleIdentifier` from `Info.plist`.
- `bundle_name` (string)
- `display_name` (string or null): `CFBundleDisplayName`.
- `extensions` (list of App Bundle): `PlugIns/*.appex`, `Extensions/*.appex` (ExtensionKit),
  `Watch/*.app`, and `AppClips/*.app`, recursively. Every nested `.app`/`.appex` that is signed
  MUST be one of these, so that it gets its own App ID and profile.

#### 4.1.11 Install Plan

The plan `install` builds before making changes. `--dry-run` prints it and exits (Section 7.5).

- `team` (Team)
- `device_udid` (string or null)
- `device_action` (`none` | `register` | `skip`)
- `certificate_action` (`reuse <serial>` | `create` | `revoke_and_create <serials>`)
- `app_ids` (list of `{identifier, exists}`)
- `app_ids_to_register` (integer)
- `available_quantity` (integer)
- `app_group` (`{identifier, exists}`)
- `feasible` (boolean), plus the reason (error code) when `false`

### 4.2 Stable Identifiers and Normalization Rules

- `Key ID`
  - The SHA-1 hash of the lowercased `apple_id`, as lowercase hexadecimal.
  - The key file path is `<config_dir>/keys/<key_id>/key.pem`.
- `Main Bundle ID`
  - The value of `--bundle-id` when given.
  - Otherwise `<original CFBundleIdentifier>.<team_id>`.
- `Extension Bundle ID`
  - Each extension's original bundle identifier MUST start with the main bundle's original
    identifier and be strictly longer than it. Otherwise fail with `bundle_invalid`.
  - The new identifier is `<Main Bundle ID>` followed by the remainder of the original identifier
    after removing the main bundle's original identifier prefix.
- `App ID Name`
  - The bundle name with every character other than ASCII letters and digits removed (Apple
    rejects others). If the result is empty, use the bundle identifier reduced the same way.
- `App Group ID`
  - `group.<Main Bundle ID>`. Its name is `app group for <App ID Name of the main bundle>`.
  - The Developer Service Client MAY remove characters Apple rejects from App ID and App Group
    names before sending them.
- `Sideloader Certificate`
  - A development certificate with `machine_name == "Sideloader"`.
- `Matching Certificate`
  - A Sideloader Certificate whose public key matches the local private key.
- `Identifier Match`
  - Arguments of `cert revoke`, `app-id delete`, and similar commands are matched exactly
    (case-sensitive).

## 5. Command-Line Interface Specification

### 5.1 Executable Name

The executable name is Implementation-defined.

- The implementation in this repository uses `sideload`.
- Examples in this document write it as `<cli>`.
- The environment variable prefix is `SIDELOAD_` regardless of the executable name.
- The configuration directory name is `Sideload` regardless of the executable name.
- The certificate machine name (`Sideloader`) MUST stay fixed, so that certificates created by
  upstream Sideloader and by this tool are recognized by both.

### 5.2 Command Tree

```text
<cli> [global options] <command>

<cli> install <ipa> [install options]     Install an IPA onto a device
<cli> install -s [install options]        Install the latest SideStore release

# Diagnostics (Section 8)
<cli> team list                           Check login and look up team IDs
<cli> device list [--udid <UDID>]         Registered and connected devices
<cli> device delete <device_id>           Unregister a device
<cli> device pairing-file [--udid <UDID>] [-o <path>]
                                          Export a pairing file (Section 8.9)
<cli> cert list                           List development certificates
<cli> cert revoke <serial_number>         Revoke a development certificate
<cli> app-id list                         List App IDs and remaining quota
<cli> app-id delete <identifier>          Delete an App ID

<cli> logout                              Remove the saved login session (Section 9.6)
<cli> version                             Print the version
```

`--team <team_id>` is accepted by `install` and by every diagnostic command except `team list`
and `version`.

### 5.3 Global Options

Global options come before the subcommand.

- `-d`, `--debug`
  - Sets the log level to the most verbose level (TRACE or equivalent).
- `--thread-count <N>`
  - Signing parallelism. A positive integer. Defaults to the number of logical CPUs.
- `--anisette-server <URL>`
  - Use a remote Anisette server. When omitted, local ADI is used.

### 5.4 Install Options

- `<ipa>`: The IPA to install. Must pass the validation in Section 5.6. Exactly one of `<ipa>`
  and `--sidestore` MUST be given.
- `-s`, `--sidestore`: Download and install the latest SideStore release instead of `<ipa>`
  (Section 7.7).
- `--udid <UDID>`: Target device.
- `--team <team_id>`: Team to use.
- `-o`, `--output <path>`: Write the signed IPA instead of installing it.
- `--dry-run`: Print the plan only. Changes nothing on the Apple side or on the device.
- `--strip-extensions`: Remove extensions, Watch apps, and App Clips before processing.
- `--bundle-id <id>`: Set the main bundle identifier (Section 4.2).
- `--name <name>`: Rewrite `CFBundleDisplayName`.
- `--new-cert`: Do not reuse the existing certificate; recreate it (Section 7.3).
- `--keep-temp`: Do not delete the working directory.

`--output` and `--dry-run` MUST NOT be combined, and exactly one of `<ipa>` and `--sidestore`
MUST be given (neither, or both, is an error); the CLI MUST reject these with `invalid_arguments`.

### 5.5 Exit Codes

- `0`: Success, including `--dry-run` when the plan is feasible (`feasible = true`).
- `1`: Failure, i.e. any error in Section 13.1, including `--dry-run` when the plan is not
  feasible.

Argument parsing failures also exit with `1`. Printing help (`--help`) exits with `0`.

### 5.6 Argument Validation and Error Surface

The following MUST be validated before login or any device communication starts:

- When `--sidestore` is not given, `<ipa>` is given, exists, is a regular file, and has the `.ipa` extension → otherwise `ipa_not_found` /
  `ipa_invalid`.
- `--output` and `--dry-run` are not both given → `invalid_arguments`.
- Exactly one of `<ipa>` and `--sidestore` is given → `invalid_arguments`.
- The parent directory of the `--output` path exists → `output_write_failed`.
- `--thread-count` is a positive integer → `invalid_arguments`.
- `--anisette-server` is an `http` or `https` URL → `invalid_arguments`.
- `--bundle-id` contains only characters valid in a bundle identifier (`[A-Za-z0-9.-]`) →
  `invalid_arguments`.

## 6. Configuration Specification

### 6.1 Configuration Resolution Pipeline

Each configuration value is resolved in this order of precedence:

1. CLI option
2. Environment variable (Section 6.2)
3. Interactive input (credentials only; Section 9.2)
4. Default value

When both a CLI option and an environment variable are present, the CLI option MUST win.

### 6.2 Environment Variables

- `SIDELOAD_CONFIG_DIR`
  - Overrides the configuration directory.
- `SIDELOAD_ANISETTE_SERVER`
  - Default for `--anisette-server`.
- `SIDELOAD_APPLE_ID`
  - Apple ID. When set, the tool does not prompt for the Apple ID.
- `SIDELOAD_APPLE_PASSWORD`
  - Password. When set, the tool does not prompt for the password.
- `SIDELOAD_NO_KEYCHAIN`
  - When non-empty, login sessions are neither saved nor reused (Section 9.6).
- `HTTPS_PROXY` / `https_proxy`, `NO_PROXY` / `no_proxy`
  - Standard proxy settings. They SHOULD be honored for every HTTPS connection (an `http://`
    proxy reached with `CONNECT`).
- `SSL_CERT_FILE`
  - A PEM file of additional trust anchors (for TLS-intercepting proxies). It SHOULD be honored.

An environment variable set to the empty string MUST be treated as unset.

### 6.3 Configuration Directory Resolution

1. If `SIDELOAD_CONFIG_DIR` is set, use its value.
2. Otherwise use the per-OS default:
   - Linux and others: `${XDG_CONFIG_HOME:-~/.config}/Sideload`
   - macOS: `~/Library/Preferences/Sideload`
   - Windows: `%AppData%\Sideload`

The upstream directory (`Sideloader`) is not read. Users switching from upstream can copy its
contents into this directory.

Create the directory if it does not exist.

### 6.4 Core Config Fields Summary (Cheat Sheet)

This section is intentionally redundant with the rest of the document.

- `debug`: boolean, default `false`, `-d` / `--debug`
- `thread_count`: positive integer, default number of logical CPUs, `--thread-count`
- `anisette_server`: URL or null, default null, `--anisette-server` > `SIDELOAD_ANISETTE_SERVER`
- `config_dir`: path, `SIDELOAD_CONFIG_DIR` > per-OS default
- `apple_id`: string, `SIDELOAD_APPLE_ID` > interactive input
- `password`: string, `SIDELOAD_APPLE_PASSWORD` > interactive input (no echo)
- `team_id`: string or null, default null (first team), `--team`
- `udid`: string or null, default null (automatic selection), `--udid`

## 7. Install Pipeline

### 7.1 Modes

`install` runs in one of the following modes:

- `Install` (default): Installs onto the device.
- `Output` (`--output`): Writes the signed IPA. A connected device is OPTIONAL.
- `DryRun` (`--dry-run`): Prints the Install Plan and exits. MUST NOT write anything to the Apple
  side or to the device, and MUST NOT generate or replace the signing key. The only configuration
  directory writes allowed are those logging in itself requires: anisette state (local ADI
  libraries, `device.json`, ADI provisioning data, remote anisette state).

### 7.2 Phases

Installation proceeds through the following phases in order. Phase names MUST be used in progress
output and error reports.

1. `ValidatingArguments`: Validation from Section 5.6.
2. `SelectingDevice`: Choose the target device using the rules in Section 10.1.
3. `DownloadingApp`: Only with `--sidestore`: download the latest SideStore release into the
   working directory (Section 7.7).
4. `PreparingBundle`: Extract the IPA into the working directory, apply `--strip-extensions`
   and `--name`, and check the extension bundle identifiers (Section 4.2).
5. `PreparingAnisette`: Prepare the Anisette Provider.
6. `LoggingIn`: Log in following Section 9.2.
7. `SelectingTeam`: Choose the team using the rules in Section 9.3.
8. `Planning`: Read Apple-side state and build the Install Plan. If `feasible = false`, fail here
   (in `DryRun`, print the plan first, then exit with code 1).
9. `RegisteringDevice`: Register the device if needed.
10. `PreparingCertificate`: Prepare the certificate using the rules in Section 7.3.
11. `RegisteringAppIds`: Register missing App IDs.
12. `ConfiguringAppGroup`: Enable App Groups on every App ID, create or reuse the App Group, and
    assign it.
13. `FetchingProfiles`: For each App ID, download that App ID's provisioning profile.
14. `Signing`: Sign the main bundle and its extensions.
15. `Delivering`: In `Install` mode, transfer to and install on the device (Section 10.3). In
    `Output` mode, write the signed IPA.
16. `CleaningUp`: Delete the working directory unless `--keep-temp` is given.

Terminal states:

- `Succeeded`: Print `Done.` and exit with code 0.
- `PlanReported`: The plan was printed in `DryRun`. Exit with code 0 or 1 depending on `feasible`.
- `Failed`: Print the error code and the failing phase, and exit with code 1.

Failures that can be determined locally (arguments, the IPA, device selection) MUST be reported
before credentials are requested, and device selection before any download. This is why phases
2 to 4 come before phase 6.

### 7.3 Certificate Preparation Rules

Without `--new-cert`:

1. If the key file exists, load it. Otherwise generate a 2048-bit RSA key and save it.
2. If a Matching Certificate exists, use it.
3. Otherwise create a CSR from the key, submit it, and use the issued certificate.

With `--new-cert`:

1. Print the Sideloader Certificates to be revoked (name and serial number).
2. Revoke all of them.
3. Generate a new key, replace the key file, and submit a CSR.

During the `Planning` phase, record which of the above will happen in `certificate_action`.

The CSR subject is Implementation-defined (upstream uses
`C=US, ST=STATE, L=LOCAL, O=ORGANIZATION, CN=CN`).

### 7.4 App ID Registration Rules

- The required App IDs are the bundle identifiers of the main bundle and of the extensions that
  remain after `--strip-extensions` is applied.
- Those that do not match an already registered App ID form `app_ids_to_register`.
- If `available_quantity` is present and `app_ids_to_register` exceeds it, the tool MUST NOT
  register any of them.
  Fail with `app_id_quota_exceeded` and print the earliest `expiration_date` among the registered
  App IDs.

### 7.5 Dry-Run Plan Output

In `DryRun` mode, print the plan in the following form when phase 8 (`Planning`) completes. The exact line
format is Implementation-defined, but every item MUST be included.

```text
Team:         <name> (<team_id>)
Device:       <udid> (registered | will be registered | skipped)
Certificate:  reuse <serial> | will create new | will revoke <serial>, ... and create new
App IDs:      need N, already registered M, will register K (available: A / max: X)
              (A and X are `unlimited` when the quota is absent)
  - <bundle_id> (exists | new)
App Group:    group.<main_bundle_id> (exists | new)
Result:       OK | NG: <error_code> <reason>
```

### 7.6 Idempotency and Re-run Rules

- Already registered devices, App IDs, and App Groups MUST be reused and MUST NOT be created again.
- When an `install` that failed partway is re-run, it MUST be able to continue by reusing
  resources created by the previous run.
- The key file MUST NOT be overwritten except by `--new-cert`.

### 7.7 `--sidestore`: Latest SideStore Release

With `--sidestore`, the tool installs the latest release of SideStore instead of `<ipa>`.

1. Request `GET https://api.github.com/repos/SideStore/SideStore/releases/latest` with
   `Accept: application/vnd.github+json` and a `User-Agent` naming the tool. This endpoint returns
   the most recent non-prerelease, non-draft release.
2. Select the asset whose `name` is exactly `SideStore.ipa`. If there is none, fail with
   `download_failed` and name the release tag.
3. Print the release tag (for example `Downloading SideStore 0.6.1...`).
4. Download the asset's `browser_download_url`, following HTTPS redirects only, into the working
   directory as `SideStore.ipa`. The download MUST fail with `download_failed` when:
   - the response is not successful;
   - the body exceeds 1 GiB;
   - the asset metadata has a `size` and the body length differs;
   - the asset metadata has a `digest` of the form `sha256:<hex>` and the SHA-256 of the body
     differs.
   When no `digest` is published, integrity relies on HTTPS alone. The tool SHOULD say so with
   `--debug`.
5. Continue with `PreparingBundle` on the downloaded file. Because the bundle identifier is
   `com.SideStore.SideStore`, Section 11.1 applies (`ALTAppGroups`).

The download is not cached; each run fetches the latest release again. In `DryRun` mode the
download still happens (it changes nothing on the Apple side or on the device), so that the plan
reflects the real bundle.

## 8. Diagnostic Commands

Diagnostic commands exist to investigate and resolve the causes of `install` failures. Every one
of them except `version` logs in (Section 9.2). All except `team list` accept `--team`.

### 8.1 `team list`

Confirms that login works and prints the IDs usable with `--team`.

```text
Teams:
 - `<name>`, with ID `<team_id>`.
```

### 8.2 `device list [--udid <UDID>]`

- Prints all registered devices. Connected ones are marked `(connected)`.
- Prints connected but unregistered devices separately.
- MUST NOT fail when no device is connected.
- With `--udid`, prints only lines about that device.

```text
You have N devices registered.
 - Device `<name>` of UDID `<udid>` with the identifier `<device_id>` (connected)
Connected devices not registered:
 - `<udid>`
```

### 8.3 `device delete <device_id>`

- The argument is the `device_id`, not the UDID. The help text MUST say so.
- Fails with `device_not_found` when no device matches.

### 8.4 `cert list`

```text
You have N certificates registered.
 - `<name>` with the serial number `<serial>`, from the machine named `<machine_name>`.
```

Marking the Matching Certificate with `(this machine)` is RECOMMENDED.

### 8.5 `cert revoke <serial_number>`

- Fails with `certificate_not_found` when no certificate matches.
- When two or more match, does nothing and fails with `ambiguous_match`.
- Apps signed with a revoked certificate stop launching. The help text MUST say so.

### 8.6 `app-id list`

```text
You have <available> App IDs available out of the <max> you have at your disposal.
 - `<identifier>` for the app `<name>`, expiring on <date>.
```

### 8.7 `app-id delete <identifier>`

- Matching follows the same rules as `cert revoke` (`app_id_not_found` / `ambiguous_match`).
- Deleting does not restore quota. The help text MUST say so.

### 8.8 `version`

Prints the version string. Performs neither login nor device communication.

### 8.9 `device pairing-file [--udid <UDID>] [-o <path>]`

Writes a pairing file for the on-device app ([ios/SPEC.md](ios/SPEC.md) Section 5.1). It does
not log in.

- The device is selected as in Section 10.1 for `Install` mode, except that with `--udid` the
  device need not be connected (usbmuxd keeps the pair record).
- Reads the device's pair record from usbmuxd (`ReadPairRecord`). If there is none, fail with
  `device_not_paired`. The record MUST parse as a pairing record (Section 10).
- Writes the record as an XML plist with `UDID` set to the device's UDID, to `<path>` or by
  default `./<UDID>.mobiledevicepairing`, through a temporary file and with owner-only
  permissions. Write failures fail with `output_write_failed`.
- Prints a warning that the file grants full access to the device.

## 9. Apple Account Integration Contract

### 9.1 Anisette Provider

- Local ADI:
  - MUST be supported on Linux (x86_64, aarch64), macOS (x86_64, arm64), and Windows (x86_64).
    On any other host, the tool MUST fail with `anisette_unavailable` unless `--anisette-server` is
    given, and the message MUST suggest `--anisette-server`.
  - macOS MAY use the system AOSKit/AuthKit provider instead of Android ADI libraries.
  - For backends using Android ADI, if the libraries are missing from the configuration
    directory, download them and show progress (%).
  - Fail with `adi_download_failed` when the download fails, and with `anisette_unavailable` when
    initialization fails.
- Remote:
  - MUST NOT download the ADI libraries.
  - Fail with `anisette_unavailable` when the server is unreachable or its response is invalid.
- With either backend, error messages are RECOMMENDED to suggest switching (to `--anisette-server`,
  or back to local ADI).

### 9.2 Login Flow

1. Resolve `apple_id`: `SIDELOAD_APPLE_ID` → interactive input.
2. Resolve `password`: `SIDELOAD_APPLE_PASSWORD` → interactive input.
   - Interactive input MUST NOT be echoed. On platforms where echo cannot be suppressed, a warning
     MUST be printed before input.
3. If interactive input is needed but standard input is not a terminal, fail immediately with
   `credentials_unavailable` without waiting for input.
4. Authenticate. On failure, fail with `login_failed`, including the description and code returned
   by Apple.
5. If 2FA is requested, read codes from standard input one line at a time.
   - Reading MAY happen even when standard input is not a terminal (piped input is allowed).
   - If the input is `resend`, resend the code and wait for input again.
   - On a wrong code, ask again. When standard input reaches EOF, fail with `two_factor_failed`.
6. Do not persist credentials. The session MAY be saved only as described in Section 9.6.

### 9.3 Team Selection

- Without `--team`, use the first team in the team list.
- With `--team`, use the team whose `team_id` matches exactly. Otherwise fail with
  `team_not_found`.
- If there are no teams at all, fail with `team_not_found`.

### 9.4 Required Developer Service Operations

The Developer Service Client MUST provide at least the following operations, all for iOS:

- `list_teams()`
- `list_devices(team)`, `add_device(team, name, udid)`, `delete_device(team, device_id)`
- `list_development_certs(team)`, `submit_development_csr(team, csr_pem)` (the issued
  certificate is then found by its public key, Section 15.3),
  `revoke_development_cert(team, cert)`
- `list_app_ids(team) -> {app_ids, available_quantity, max_quantity}`,
  `add_app_id(team, identifier, name)`, `update_app_id(team, app_id, features)`,
  `delete_app_id(team, app_id)`
- `list_app_groups(team)`, `add_app_group(team, identifier, name)`,
  `assign_app_group(team, app_id, app_group)`
- `download_team_provisioning_profile(team, app_id)`

### 9.5 Error Mapping

- Transport failures (cannot connect, timeout) → `apple_transport_error`.
- Application errors returned by Apple → the code appropriate to the operation (Section 13.1), or
  `apple_api_error` when none applies. The message MUST include the result code and description
  returned by Apple.
- Unparseable responses → `apple_api_error` (with `--debug`, log the response content).

### 9.6 Saved Sessions

Where the OS provides a secure per-user store, the tool MAY save the Developer Services session so
that later commands skip steps 2 to 5 of Section 9.2. The reference implementation does this on
macOS (login Keychain, service `sideload`, account = the lowercased Apple ID) and saves nothing
on other hosts.

- What is saved: the account's `adsid`, the Xcode app token and its expiry. The password and 2FA
  codes MUST NOT be saved. Sessions without an expiry MUST NOT be saved.
- Order: resolve `apple_id` (Section 9.2 step 1) first. If a saved session for it exists and
  stays valid for at least 10 more minutes, verify it with `list_teams()`; if that succeeds, use
  it without asking for the password. Otherwise delete the saved session and log in normally.
- After a successful normal login, save the new session (replacing any old one) and tell the
  user how to remove it.
- `SIDELOAD_NO_KEYCHAIN` (non-empty) disables both saving and reusing.
- `logout` resolves `apple_id` and deletes its saved session without logging in. It succeeds
  whether or not a session was saved.
- The saved token is a secret (Section 14.2): it MUST NOT be written anywhere except the OS
  store and MUST NOT be logged.

## 10. Device Integration Contract

### 10.1 Device Selection

- With `--udid`:
  - If that device is connected, use it.
  - If it is not connected: in `Install` mode, fail with `device_not_connected`. In `Output` and
    `DryRun` modes, use the UDID even though the device is not connected.
- Without `--udid`:
  - If exactly one device is connected, use it.
  - If none is connected: in `Install` mode, fail with `no_device_connected`. In `Output` and
    `DryRun` modes, continue without a device (`device_action = skip`, print a warning).
  - If two or more are connected, fail with `multiple_devices_connected` in every mode (prompting
    the user to pass `--udid`).

### 10.2 Device Registration

- Register the target device if its UDID is not registered.
- Obtain the device name from lockdown. If it cannot be obtained (including when the device is not
  connected), use the UDID as the name.
- When there is no target device (`skip`), do not register anything. The profile then covers
  registered devices only.

### 10.3 Delivery to Device

1. Connect to lockdown and start the installation_proxy, misagent, and AFC services.
2. Prepare `PublicStaging` over AFC. If it already exists, delete it with its contents and
   recreate it.
3. Transfer the entire signed bundle to `PublicStaging/<.app directory name>`.
4. Install the downloaded provisioning profiles on the device through misagent.
5. Ask installation_proxy to install with `PackageType = Developer`, and show progress until it
   completes.
6. If installation_proxy returns an error, fail with `install_failed` and print `Error`,
   `ErrorDescription`, and `ErrorDetail`.

If lockdown cannot be reached because the device is not paired or is locked, the tool SHOULD fail
with `device_not_paired` and tell the user to choose "Trust This Computer" on the device.

## 11. Bundle Processing and Signing Contract

### 11.1 Bundle Processing

- The IPA MUST contain exactly one `Payload/<name>.app`. Otherwise fail with `ipa_invalid`.
- `--strip-extensions`: Delete `PlugIns/`, `Extensions/`, `Watch/`, and `AppClips/`.
- `--name`: Set `CFBundleDisplayName` of the main bundle.
- Rewrite bundle identifiers following Section 4.2. A nested Watch app's
  `WKCompanionAppBundleIdentifier`, when present, MUST be set to the new `Main Bundle ID`.
- `Info.plist` files MUST be written back in their original format (XML or binary).
- If the main bundle's identifier (before rewriting) is `com.SideStore.SideStore`, set
  `ALTAppGroups` in `Info.plist` to `[<App Group ID>]`.

### 11.2 Signing

- The main bundle and each extension MUST be signed with the certificate, the private key, and the
  profile of their own App ID. Implementations MUST NOT sign everything with the main bundle's
  profile, as upstream does.
- Entitlements are derived from the profile. The details are Implementation-defined.
- Parallelism follows `thread_count`. A value of `1` means sequential processing.
- On failure, fail with `signing_failed`, including the path of the file that failed.

### 11.3 Output Mode

- Write the signed `Payload/` as an IPA (ZIP) to the `--output` path.
- It is RECOMMENDED to write to a temporary file and then replace the destination, so that no
  incomplete file is left behind on failure.

## 12. Logging, Progress, and Output

- Command results such as listings MUST go to standard output. Logs, progress, and errors MUST go
  to standard error.
- The default log level is INFO or equivalent. `--debug` raises it to TRACE or equivalent.
- `install` shows the names of the phases in Section 7.2 and the overall progress, for example
  one line per phase such as `[8/16] Planning`. When standard error is not a terminal, it is
  RECOMMENDED to print one line per phase instead of a progress bar. Phases that do not apply
  (such as `DownloadingApp` without `--sidestore`) MAY be omitted.
- Errors are printed as `error[<error_code>] (<phase>): <message>`. `<phase>` is included for
  `install` only.
- With `--debug`, exception details (stack traces, summaries of HTTP requests and responses) MAY
  be printed, but MUST NOT include the secrets listed in Section 14.2.
- With `--keep-temp`, print the path of the working directory on exit (on both success and
  failure).

## 13. Failure Model and Recovery Strategy

### 13.1 Failure Classes

1. `Argument / Input Failures`
   - `invalid_arguments`
   - `ipa_not_found`
   - `ipa_invalid`
   - `bundle_invalid` (an extension's bundle identifier violates the rules)
   - `output_write_failed`

2. `Authentication Failures`
   - `adi_download_failed`
   - `anisette_unavailable`
   - `credentials_unavailable`
   - `login_failed`
   - `two_factor_failed`

3. `Account Resource Failures`
   - `team_not_found`
   - `device_limit_reached`
   - `device_not_found`
   - `certificate_limit_reached`
   - `certificate_not_found`
   - `app_id_quota_exceeded`
   - `app_id_not_found`
   - `ambiguous_match`
   - `profile_download_failed`
   - `apple_api_error`
   - `apple_transport_error`

4. `Device Failures`
   - `no_device_connected`
   - `multiple_devices_connected`
   - `device_not_connected`
   - `device_not_paired`
   - `device_transport_error`
   - `install_failed`

5. `Artifact Failures`
   - `signing_failed`
   - `download_failed` (the `--sidestore` download in Section 7.7)

6. `Unexpected Failures`
   - `internal_error` (an implementation defect; details are printed with `--debug`)

### 13.2 Recovery Behavior

- The tool does not retry automatically. However, it MAY retry transient transport failures
  (`apple_transport_error`, `device_transport_error`) a bounded number of times. The number is
  Implementation-defined.
- On failure, the tool stops and does not delete Apple-side resources it has created so far (a
  re-run reuses them).
- The working directory MUST be deleted on failure as well, unless `--keep-temp` is given.

### 13.3 Operator Intervention Points

The actions available to the user for each kind of failure are listed below. Error messages are
RECOMMENDED to include the relevant action.

- `login_failed` / `two_factor_failed`
  - Try login alone with `team list`.
- `anisette_unavailable` / `adi_download_failed`
  - Switch to `--anisette-server`, or conversely back to local ADI.
- `team_not_found`
  - Check the ID with `team list`.
- `device_limit_reached`
  - Inspect with `device list` and remove unneeded registrations with `device delete`.
- `certificate_limit_reached`, or a suspected certificate inconsistency
  - Inspect with `cert list` and revoke unneeded certificates with `cert revoke`.
  - Or recreate the certificate with `install --new-cert`.
- `app_id_quota_exceeded`
  - Check expiration dates with `app-id list` and wait.
  - Or reduce the number needed with `install --strip-extensions`.
- `signing_failed` / `install_failed`
  - Run `install --output` to sign only, isolating whether signing or transfer is the problem.
  - Inspect the signed bundle with `--keep-temp`.
  - Get detailed logs with `--debug`.
- `download_failed`
  - Check the network (and `HTTPS_PROXY`), or download `SideStore.ipa` manually and pass its
    path as `<ipa>` instead of `--sidestore`.
- To preview the outcome before running
  - `install --dry-run`.

### 13.4 Irreversible Operations

The following operations cannot be undone, or are not fully reverted when undone:

- Registering an App ID: deleting it does not restore quota.
- Revoking a certificate (`cert revoke`, `install --new-cert`): apps signed with that certificate
  stop launching.
- Registering a device: on paid accounts, deleting it does not restore the yearly quota.

Thanks to the pre-check in Section 7.4, `install` MUST NOT register a partial set of App IDs when
the quota is insufficient.

## 14. Security and Operational Safety

### 14.1 Trust Boundary Assumption

- The tool is intended to run on the user's own machine against the user's own Apple account.
- Credentials MUST NOT be sent anywhere other than Apple's authentication servers. In particular,
  credentials are never sent to a remote Anisette server (it is used only to obtain Anisette data).
- A remote Anisette server is a third party that generates Anisette data containing device
  identifiers. The help text is RECOMMENDED to say so.

### 14.2 Secret Handling

- Passwords, 2FA codes, authentication tokens, and private keys MUST NOT be logged, including with
  `--debug`.
- The value of `SIDELOAD_APPLE_PASSWORD` MUST NOT be printed. The fact that it is set MAY be
  logged (with `--debug`).
- Passing the password through an environment variable may expose it to other processes of the
  same user. The help text is RECOMMENDED to say so.
- The password MUST NOT be accepted as a CLI option, because it would be visible in the process
  list.

### 14.3 Filesystem Safety Requirements

- Key files MUST be created readable and writable by the owner only (`0600` on POSIX). The key
  directory is RECOMMENDED to be `0700`.
- The working directory MUST be created under the OS temporary directory with a hard-to-guess
  name.
- When extracting the IPA, entries containing `..` or absolute paths, and symbolic links pointing
  outside the working directory, MUST be rejected (`ipa_invalid`).

### 14.4 Downloaded Applications

- The `--sidestore` download (Section 7.7) MUST use only the fixed repository `SideStore/SideStore`
  and HTTPS for every request, including redirects.
- A published SHA-256 digest MUST be verified before the file is used.
- The downloaded file is treated like a user-supplied IPA: the extraction rules of Section 14.3
  apply.

### 14.5 Destructive Operation Safety

- `install --new-cert` and `cert revoke` MUST print the certificates to be revoked before
  revoking them.
- Deletions and revocations whose match hits more than one item MUST NOT be performed
  (`ambiguous_match`).

## 15. Reference Algorithms (Language-Agnostic)

### 15.1 Install

```text
function install(args):
  validate_arguments(args)                          # ValidatingArguments
  target = select_device(args.udid, args.mode)      # SelectingDevice
  ipa = args.sidestore ? download_latest_sidestore() : args.ipa  # DownloadingApp
  bundle = prepare_bundle(ipa, args)                # PreparingBundle

  anisette = prepare_anisette(config)               # PreparingAnisette
  session = login(anisette, resolve_credentials())  # LoggingIn
  team = select_team(session, args.team)            # SelectingTeam

  plan = build_plan(session, team, target, bundle, args)   # Planning
  if args.mode == DryRun:
    print_plan(plan)
    return plan.feasible ? 0 : 1
  if not plan.feasible:
    fail(plan.error)

  if plan.device_action == register:
    session.add_device(team, device_name(target), target.udid)  # RegisteringDevice
  identity = prepare_certificate(session, team, args.new_cert)   # PreparingCertificate
  app_ids = register_app_ids(session, team, bundle, plan)        # RegisteringAppIds
  group = configure_app_group(session, team, app_ids, bundle)    # ConfiguringAppGroup
  profiles = {}
  for app_id in app_ids:                                         # FetchingProfiles
    profiles[app_id.identifier] = session.download_team_provisioning_profile(team, app_id)
  sign(bundle, identity, profiles, config.thread_count)          # Signing

  if args.mode == Output:                                        # Delivering
    write_ipa(bundle, args.output)
  else:
    deliver(target, bundle, profiles.values())
  cleanup(args.keep_temp)                                        # CleaningUp
  print("Done.")
  return 0
```

### 15.2 Build Plan

```text
function build_plan(session, team, target, bundle, args):
  plan = {team: team}

  if target is null:
    plan.device_action = skip
  else:
    devices = session.list_devices(team)
    plan.device_action = any(d.udid == target.udid for d in devices) ? none : register

  plan.certificate_action = decide_certificate_action(session, team, args.new_cert)

  rewrite_bundle_ids(bundle, team, args.bundle_id)
  listed = session.list_app_ids(team)
  needed = [bundle] + bundle.extensions
  plan.app_ids = [{identifier: b.bundle_identifier,
                   exists: any(a.identifier == b.bundle_identifier for a in listed.app_ids)}
                  for b in needed]
  plan.app_ids_to_register = count(x for x in plan.app_ids if not x.exists)
  plan.available_quantity = listed.available_quantity    # null = unlimited

  groups = session.list_app_groups(team)
  group_id = "group." + bundle.bundle_identifier
  plan.app_group = {identifier: group_id, exists: any(g.identifier == group_id for g in groups)}

  if plan.available_quantity is not null and plan.app_ids_to_register > plan.available_quantity:
    plan.feasible = false
    plan.error = app_id_quota_exceeded(min(a.expiration_date for a in listed.app_ids))
  else:
    plan.feasible = true
  return plan
```

### 15.3 Prepare Certificate

```text
function prepare_certificate(session, team, new_cert):
  key_path = config_dir / "keys" / hex_lower(sha1(apple_id)) / "key.pem"
  sideloader_certs = [c for c in session.list_development_certs(team)
                      if c.machine_name == "Sideloader"]

  if new_cert:
    print_certificates_to_revoke(sideloader_certs)
    for c in sideloader_certs:
      session.revoke_development_cert(team, c)
    key = generate_rsa_2048()
    write_private(key_path, key)                  # mode 0600
  else if exists(key_path):
    key = read_key(key_path)
    for c in sideloader_certs:
      if public_key(c.content) == public_key(key):
        return identity(c, key)
  else:
    key = generate_rsa_2048()
    write_private(key_path, key)

  session.submit_development_csr(team, make_csr(key))
  cert = find(c in session.list_development_certs(team)
              if c.machine_name == "Sideloader" and public_key(c.content) == public_key(key))
  return identity(cert, key)
```

### 15.4 Select Device

```text
function select_device(udid, mode):
  connected = usbmux_list_devices()
  if udid is not null:
    if udid in connected: return connected[udid]
    if mode == Install: fail(device_not_connected)
    return {udid: udid, connected: false}
  if len(connected) == 1: return connected[0]
  if len(connected) > 1: fail(multiple_devices_connected)
  if mode == Install: fail(no_device_connected)
  warn("no device connected; the profile will cover registered devices only")
  return null
```

## 16. Test and Validation Matrix

A conforming implementation SHOULD include tests that cover the behaviors defined in this
specification.

Validation profiles:

- `Core Conformance`: deterministic tests REQUIRED for all conforming implementations. Apple
  services and devices are replaced with mocks.
- `Real Integration Profile`: checks against a real Apple account and device, RECOMMENDED before
  production use.

Unless otherwise noted, Sections 16.1 through 16.6 are `Core Conformance`.

### 16.1 CLI and Arguments

- Commands outside the command tree (Section 5.2) are rejected.
- Combining `--output` and `--dry-run` fails with `invalid_arguments`.
- A nonexistent IPA, a directory, or a file without the `.ipa` extension fails before login.
- Success exits with 0, failure with 1.

### 16.2 Configuration

- CLI options take precedence over environment variables.
- Environment variables set to the empty string are treated as unset.
- `SIDELOAD_CONFIG_DIR` overrides the configuration directory.
- On Linux, `XDG_CONFIG_HOME` is honored.

### 16.3 Credentials and Login

- When `SIDELOAD_APPLE_ID` and `SIDELOAD_APPLE_PASSWORD` are set, no input is requested.
- When only one of them is set, only the other is requested.
- When interactive input is needed and standard input is not a terminal, the tool fails with
  `credentials_unavailable` without waiting.
- `resend` during 2FA resends the code. EOF fails with `two_factor_failed`.
- The password never appears in logs (including with `--debug`).

### 16.4 Selection Rules

- Team: the first team when not specified; `team_not_found` when the specified team does not
  match.
- Device: every branch of Section 15.4 (mode × number of connected devices × presence of
  `--udid`).
- With multiple devices connected and no `--udid`, the tool fails in every mode and does not
  continue.

### 16.5 Install Pipeline

- Bundle identifier rewriting (with and without `--bundle-id`, extension prefixes, and
  `bundle_invalid` on rule violations).
- When App ID quota is insufficient, no App ID is registered.
- Each extension is signed with the profile of its own App ID.
- `--strip-extensions` reduces the required App IDs to one.
- `--dry-run` never writes to the Apple side or the device, and never generates a key.
- `--dry-run` exits with 1 when the plan is not feasible.
- `--new-cert` revokes every Sideloader Certificate and replaces the key; otherwise the key is
  never overwritten.
- A re-run after a partial failure does not create duplicate resources.
- The working directory is kept or removed according to `--keep-temp` (including on failure).
- The IPA written by `--output` contains the signed bundle when extracted.
- `--sidestore`: asset selection by exact name, failure when the asset is missing, size and
  SHA-256 digest mismatches fail with `download_failed`, and redirects to plain HTTP are refused.

### 16.6 Diagnostic Commands

- Each listing command prints every item specified in Section 8.
- `device list` succeeds with no device connected.
- `cert revoke` and `app-id delete` fail with the not-found code on zero matches and with
  `ambiguous_match` on two or more, without changing anything.

### 16.7 Real Integration Profile (RECOMMENDED)

- With a free account and a real device, `install` of an IPA containing extensions succeeds and
  the app launches.
- Reinstalling the same IPA reuses the App IDs and the certificate.
- Login works with both local ADI and remote Anisette.
- These checks MAY be skipped in CI where credentials or devices are unavailable. A skipped check
  SHOULD be reported as skipped, not as passed.

## 17. Implementation Checklist (Definition of Done)

### 17.1 REQUIRED for Conformance

- The command tree and global options in Section 5.2
- Configuration resolution in Section 6 (CLI > environment > interactive input > default)
- Passing credentials through environment variables (`SIDELOAD_APPLE_ID`,
  `SIDELOAD_APPLE_PASSWORD`)
- Password input without echo, and `resend` for 2FA
- Support for both local ADI and remote Anisette
- All phases in Section 7.2, with error reports that name the phase
- All `install` options (`--udid`, `--team`, `--output`, `--dry-run`, `--strip-extensions`,
  `--bundle-id`, `--name`, `--new-cert`, `--keep-temp`)
- App ID quota pre-check (no partial registration)
- Per-App-ID profile retrieval and signing
- `install --sidestore` (Section 7.7)
- The diagnostic commands in Section 8
- The error codes in Section 13.1 and the exit codes
- Secret handling and filesystem safety in Section 14

### 17.2 RECOMMENDED Extensions (Not REQUIRED for Conformance)

- Machine-readable output for listing commands (for example `--json`)
- Device connection over Wi-Fi
- Saved sessions in the OS keyring on hosts other than macOS (Section 9.6)

### 17.3 Operational Validation Before Production (RECOMMENDED)

- Run the `Real Integration Profile` in Section 16.7 on each target OS (Linux, macOS, Windows).
- Verify that the contents of an upstream Sideloader configuration directory, copied into this
  tool's directory, are reused as-is (keys and ADI state).

## Appendix A. Differences from Upstream Sideloader CLI

### A.1 Removed Commands

| Command | Reason |
|---|---|
| `sign` | Performed inside `install`. Standalone use requires having the certificate locally, which makes it unsuitable for diagnostics. Replaced by `install --output` |
| `trollsign` | Unrelated to installation (for TrollStore) |
| `tool list` / `tool run` | Unrelated to installation (for SideStore pairing files). `device pairing-file` exports a pairing file instead |
| `cert submit` | Done automatically by `install` |
| `app-id add` / `app-id download` | Done automatically by `install` |
| `device add` | Done automatically by `install` |

### A.2 Behavior Changes and Bug Fixes

1. Login is always performed, except that on macOS a saved session is reused (Section 9.6).
   Upstream always failed without `-i` (the keyring code was unimplemented and its condition was
   inverted). `-i` is removed; `logout` is added.
2. Credentials can also be passed through environment variables (`SIDELOAD_APPLE_ID`,
   `SIDELOAD_APPLE_PASSWORD`).
3. With multiple devices connected and no `--udid`, the tool exits with an error. Upstream printed
   an error but kept going with a null UDID.
4. Each extension is signed with the profile of its own App ID. Upstream downloaded the main
   bundle's profile for every App ID.
5. On Linux, the configuration path honors `XDG_CONFIG_HOME`. Upstream read the nonexistent
   `XDG_CONFIG_DIR`.
6. Arguments and device selection are validated before credentials are requested.
7. `install` gains `--team`, `--output`, `--dry-run`, `--strip-extensions`, `--bundle-id`,
   `--name`, `--new-cert`, and `--keep-temp`.
8. The global option `--anisette-server` (environment variable `SIDELOAD_ANISETTE_SERVER`) is
   added.
9. `--singlethread` is removed in favor of `--thread-count 1`. The default changes from `uint.max`
   to the number of logical CPUs.
10. `device list` also shows connected devices.
11. The executable name is Implementation-defined (upstream uses `sideloader`; this repository's
    implementation uses `sideload`).
12. Errors are reported with an error code and the phase name.
13. `install --sidestore` downloads and installs the latest SideStore release from GitHub.
14. The configuration directory is named `Sideload` (upstream: `Sideloader`) and environment
    variables use the `SIDELOAD_` prefix. Upstream's directory is not read.
