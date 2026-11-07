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
