//! Apple account and Developer Services integrations. Requests use verified TLS
//! and do not follow redirects across authentication trust boundaries.
pub mod developer;
pub mod gsa;

use crate::{
    Error, ErrorCode, Result,
    net::{
        NetResult,
        http::{Client, Request, Response, Url},
    },
};
/// Injectable network boundary for deterministic tests. Production uses Https.
pub trait Transport {
    fn send(&mut self, request: &Request) -> NetResult<Response>;
}
pub struct Https(Client);
// Published at https://www.apple.com/certificateauthority/AppleRootCA-G3.cer.
// Android client-info can select gsd.apple.com, whose chain ends at this root.
pub(crate) const APPLE_ROOT_G3: &[u8] = include_bytes!("certs/AppleRootCA-G3.cer");
impl Https {
    pub fn new() -> Result<Self> {
        Ok(Self(
            Client::new(
                concat!("sideload/", env!("CARGO_PKG_VERSION")),
                &[
                    crate::sign::apple_certs::ROOT_CA.to_vec(),
                    APPLE_ROOT_G3.to_vec(),
                ],
            )
            .map_err(|_| {
                Error::new(
                    ErrorCode::AppleTransportError,
                    "cannot initialize Apple TLS client",
                )
            })?,
        ))
    }
}
impl Transport for Https {
    fn send(&mut self, request: &Request) -> NetResult<Response> {
        self.0.send_without_redirects(request)
    }
}
pub(crate) fn endpoint(url: &str) -> Result<()> {
    let u = Url::parse(url)
        .map_err(|_| Error::new(ErrorCode::AppleApiError, "invalid Apple endpoint"))?;
    if !u.tls || u.port != 443 || !(u.host == "apple.com" || u.host.ends_with(".apple.com")) {
        return Err(Error::new(
            ErrorCode::AppleApiError,
            "refusing non-Apple HTTPS endpoint",
        ));
    }
    Ok(())
}
/// With `--debug`, logs a response Apple sent that could not be used
/// (SPEC Section 9.5) without leaking secrets (SPEC Section 14.2): known
/// secrets are replaced, every long token-like run (base64, hex, JWT) is
/// masked, control characters are dropped, and the text is truncated.
pub(crate) fn debug_response(what: &str, status: u16, body: &[u8], secrets: &[&str]) {
    if crate::output::debug_enabled() {
        crate::output::debug(format!(
            "{what}: unusable response (HTTP {status}, {} bytes): {}",
            body.len(),
            redact_response(body, secrets)
        ));
    }
}

/// Runs of at least this many token characters are masked.
const TOKEN_RUN: usize = 24;

fn redact_response(body: &[u8], secrets: &[&str]) -> String {
    let text = String::from_utf8_lossy(&body[..body.len().min(64 * 1024)]);
    let mut text = text.into_owned();
    for secret in secrets {
        if !secret.is_empty() {
            text = text.replace(secret, "<redacted>");
        }
    }
    let token_char = |c: char| c.is_ascii_alphanumeric() || "+/=_-.".contains(c);
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= TOKEN_RUN {
            out.push_str("<redacted>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if token_char(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            if !c.is_control() {
                out.push(c);
            }
        }
    }
    flush(&mut run, &mut out);
    out.chars().take(1024).collect()
}

pub(crate) fn description(text: &str, secrets: &[&str]) -> String {
    let mut s = text.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            s = s.replace(secret, "<redacted>");
        }
    }
    s.chars().filter(|c| !c.is_control()).take(512).collect()
}

#[cfg(test)]
mod debug_response_tests {
    use super::redact_response;

    #[test]
    fn redacts_secrets_and_token_like_runs() {
        let body = b"<html>Error 500: session T0KEN abc\n\
            dGhpcyBpcyBhIGxvbmcgYmFzZTY0IHRva2Vu== Bad Gateway</html>";
        let out = redact_response(body, &["T0KEN"]);
        assert_eq!(
            out,
            "<html>Error 500: session <redacted> abc<redacted> Bad Gateway</html>"
        );
        assert!(redact_response(&[b'a'; 5000], &[]) == "<redacted>");
        assert!(
            redact_response("é".repeat(2000).as_bytes(), &[])
                .chars()
                .count()
                <= 1024
        );
    }
}

#[cfg(test)]
mod tls_root_tests {
    #[test]
    fn apple_g3_matches_the_published_fingerprint_and_parses_as_a_trust_anchor() {
        assert_eq!(
            crate::crypto::hex(&crate::crypto::sha256(super::APPLE_ROOT_G3)),
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
        );
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                super::APPLE_ROOT_G3.to_vec(),
            ))
            .unwrap();
        assert_eq!(roots.len(), 1);
    }
}
