# Remote anisette v3

`anisette::provider(&settings)` selects the remote backend when `anisette_server` is set.
The provider implements `AnisetteProvider::headers()`. It can also be constructed directly:

```rust
use sideload::anisette::{AnisetteProvider, remote_v3::RemoteV3};
use std::path::Path;

// Use the same config directory on subsequent runs to reuse the ADI identity.
let mut provider = RemoteV3::new("http://localhost:6969", Path::new("config"))?;
let headers = provider.headers()?;
# Ok::<(), sideload::Error>(())
```

The backend fetches `/v3/client_info` and provisions on first use. It reads provisioning
endpoints from Apple's HTTPS lookup, opens `/v3/provisioning_session` over WebSocket, then
relays the identifier, `spim`, and `ptm`/`tk` exchange. It accepts only HTTPS provisioning
endpoints on `apple.com` or its subdomains, and does not follow redirects during these requests.
The WebSocket protocol sequence and binary base64 values are checked before ADI state is saved.
No Apple ID, password, 2FA code, or login session is accepted by this API.

Each `headers()` call posts to `/v3/get_headers` for a fresh OTP. The returned data contains
machine/OTP/routing values plus the stable device UUID, SHA-256 local user identifier, client
info and its matching User-Agent, current UTC time, UTC timezone, locale, and default serial number `0`. Debug output
contains header names only. Invalid replies and transport failures map to `anisette_unavailable`
without including response bodies or provisioning secrets in errors.

Persistent state is stored under:

```text
<config_dir>/anisette/<sha256(normalized_server_url)>/state.plist
```

The plist contains `keychain_identifier` (16 bytes) and optional `adi_pb` data. Server-specific
storage prevents changing servers from sending the previous server's state to another service.
New directories are private (`0700` on Unix); state files are written via a private (`0600`)
temporary sibling and replaced atomically. Symlink state directories/files are rejected.
Malformed or unreadable state fails explicitly instead of silently replacing the identity;
`RemoteV3::state_path()` identifies the file to remove when intentionally resetting it.
This format is compatible with the v3 state fields, but does not import an upstream global
`state.plist` automatically.

If the server reports ADI error `-45061`, the provider clears the blob and reprovisions once,
keeping the same identifier. It returns an error if the retry still reports invalid state.
Other protocol failures are not automatically retried.

Plain HTTP and `ws://` work for local servers; HTTPS and `wss://` use verified TLS. HTTP_PROXY
uses absolute-form requests for plain HTTP and WebSocket upgrades; HTTPS_PROXY uses CONNECT
for TLS. Lowercase proxy variables and NO_PROXY are supported. A remote server receives device
identifiers and ADI provisioning data; use a server you trust.

## Validation and remaining work

`cargo test` uses mock Apple/anisette transports to cover a complete provisioning exchange,
state reuse across provider instances, fresh headers, bounded reprovisioning, protocol order,
malformed state/responses, private file modes, and symlink rejection. A local TCP proxy test
checks that plain HTTP sends an absolute-form GET instead of CONNECT. WebSocket tests cover
handshake validation, fragments with ping/pong, close, and invalid/reserved/masked server frames.
The TCP test needs permission to bind a loopback port in restricted execution environments.

These checks do not contact live Apple or anisette services. Live interoperability remains
unverified. Apple login and Developer Services APIs and diagnostic commands are implemented; install
wiring remains pending. The provider factory selects local ADI by default on supported Linux
hosts; see LOCAL_ADI.md for its partial rollout and remaining platform/validation work.

## Authentication compatibility

Cached provisioning is bound to the server's `client_info` and `user_agent` together.
A legacy cache without metadata, or a changed provider identity, requires new provisioning.
The previous file is preserved until the replacement succeeds. These values are forwarded
unchanged; a Mac label alone does not make Android ADI acceptable to Apple.

GSA uses one fresh Anisette snapshot for each operation's HTTP headers and CPD, and pins
its device ID, client info and User-Agent throughout sign-in. On SRP init `hsc 434`, the
remote backend sends `sim`, `device_id` and `md_lu` alongside `identifier` and `adi_pb` to
`/v3/get_headers`. This requires a server implementing resync; failure is explicit and
never switches identities or servers. A valid returned `adi_pb` replaces the cached blob.
Only one resync is attempted. Local backends currently report unsupported.
