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
impl Https {
    pub fn new() -> Result<Self> {
        Ok(Self(
            Client::new(
                concat!("sideload/", env!("CARGO_PKG_VERSION")),
                &[crate::sign::apple_certs::ROOT_CA.to_vec()],
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
pub(crate) fn description(text: &str, secrets: &[&str]) -> String {
    let mut s = text.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            s = s.replace(secret, "<redacted>");
        }
    }
    s.chars().filter(|c| !c.is_control()).take(512).collect()
}
