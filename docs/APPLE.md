# Apple service APIs

`apple::gsa::Gsa::new(anisette)` creates a verified-TLS client. Call `login` with
resolved `Credentials` and a callback such as `credentials::prompt_two_factor_code`.
`authenticate` also accepts an explicit Apple ID/password and callback; it lowercases
the Apple ID. Nothing is persisted. The resulting `Session` contains the ADSID and
Xcode authorization token, with redacted Debug output. `into_parts` transfers the
transport and anisette provider to the Developer Services layer.

GSA implements lookup, SRP `s2k`/`s2k_fo`, mandatory M2 verification, CBC SPD decryption,
trusted-device 2FA, and authenticated GCM (`XYZ` plus 16-byte IV) Xcode app tokens.
Wrong verification codes re-prompt; `Resend` sends another device challenge; callback
errors/EOF abort. Successful 2FA triggers one fresh SRP login. SMS/extra account repair
flows are rejected with an explicit error. Iteration counts and response sizes are
bounded. Requests only use Apple HTTPS endpoints and never follow redirects.
TLS verification remains enabled, including debug builds; Mozilla roots and Apple's
bundled root are trusted. This is trust-store verification, not leaf/SPKI pinning.

`apple::Transport` is injectable for tests. Tests use an independent SRP server to
verify both password protocols, proof mismatch, 2FA retries/relogin, app-token checksum
and GCM authentication. No real Apple account was used; live interoperability remains
unverified. These APIs are not yet wired to diagnostic commands or `install`.

## Developer Services

`Developer::from_authenticated(session, gsa)` reuses the authenticated transport and
anisette provider. `Developer::new` creates another verified-TLS transport when needed.
Every operation supplies fresh anisette, `X-Apple-GS-Token`, ADSID, QH65B2/client IDs,
a random request UUID, and locale. Operations cover SPEC 9.4's teams, devices,
development certificates, App IDs/quota, groups/assignment, and profiles. Team listing
uses the platform-independent route; other calls use the iOS route. Certificates known
to belong to another platform are filtered out.

Mutation arguments are explicit Apple identifiers. Callers implement dry-run planning,
quota preflight, ambiguity checks, and printing certificates before revocation; the
transport never retries mutations. Nonzero result codes fail even when a partial payload
is present. Errors include the result code and sanitized description; unrecognized codes
use `apple_api_error`. Explicit limit descriptions map to the corresponding resource
limit error. Profile responses must match the requested `appIdId`.

`make_csr` produces a PKCS#10 SHA256/RSA CSR. `submit_development_csr` uses machine name
`Sideloader` and returns Apple's certRequestId; list certificates afterwards to retrieve
the issued certificate. The CSR is checked by OpenSSL in tests. Mock API tests exercise
every operation, metadata, error payloads, profile isolation, and reserved feature keys.
Live Developer Services mutations were not run.
