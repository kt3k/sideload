//! GrandSlam SRP authentication, trusted-device 2FA, and Xcode app tokens.
//! Sessions remain in memory; passwords, proofs, SPD, and tokens are not logged.
use super::{Https, Transport, description, endpoint};
use crate::{
    Error, ErrorCode, Result,
    anisette::AnisetteProvider,
    credentials::{CodeInput, Credentials},
    crypto::{
        self, cbc, gcm,
        srp::{Protocol, SrpClient},
    },
    formats::{
        base64,
        plist::{self, Dictionary, Value},
    },
    net::http::Request,
};
const LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const APP: &str = "com.apple.gs.xcode.auth";
const MAX_BODY: usize = 4 * 1024 * 1024;
fn failed(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::LoginFailed, message)
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| failed(format!("missing GSA field {key}")))
}
fn data<'a>(v: &'a Value, key: &str) -> Result<&'a [u8]> {
    v.get(key)
        .and_then(Value::as_data)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| failed(format!("missing GSA data {key}")))
}
fn status(v: &Value) -> &Value {
    v.get("Status").unwrap_or(v)
}
fn code(v: &Value) -> Option<i64> {
    status(v).get("ec").and_then(Value::as_i64)
}
fn check(v: &Value, secrets: &[&str], error: ErrorCode) -> Result<()> {
    let c = code(v).ok_or_else(|| Error::new(error, "GSA response has no status code"))?;
    if c != 0 {
        return Err(Error::new(
            error,
            format!(
                "Apple error {c}: {}",
                description(
                    status(v)
                        .get("em")
                        .and_then(Value::as_str)
                        .unwrap_or("authentication rejected"),
                    secrets
                )
            ),
        ));
    }
    Ok(())
}
/// In-memory developer authorization. Debug never prints the token.
pub struct Session {
    pub adsid: String,
    pub(crate) token: String,
    pub expiry: Option<u64>,
}
impl Session {
    /// Authorization token for Apple Developer Services; never log this value.
    pub fn token(&self) -> &str {
        &self.token
    }
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("adsid", &self.adsid)
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}
pub struct Gsa<T = Https> {
    transport: T,
    anisette: Box<dyn AnisetteProvider>,
    urls: Option<Dictionary>,
}
impl Gsa<Https> {
    pub fn new(anisette: Box<dyn AnisetteProvider>) -> Result<Self> {
        Ok(Self::with_transport(anisette, Https::new()?))
    }
}
impl<T: Transport> Gsa<T> {
    pub fn with_transport(anisette: Box<dyn AnisetteProvider>, transport: T) -> Self {
        Self {
            transport,
            anisette,
            urls: None,
        }
    }
    pub fn into_parts(self) -> (T, Box<dyn AnisetteProvider>) {
        (self.transport, self.anisette)
    }
    pub fn login(
        &mut self,
        credentials: &Credentials,
        mut input: impl FnMut() -> Result<CodeInput>,
    ) -> Result<Session> {
        self.authenticate(
            &credentials.apple_id.to_lowercase(),
            credentials.password(),
            &mut input,
        )
    }
    /// Authenticate supplied credentials without retaining or persisting them.
    pub fn authenticate(
        &mut self,
        apple_id: &str,
        password: &str,
        input: &mut impl FnMut() -> Result<CodeInput>,
    ) -> Result<Session> {
        let username = apple_id.to_lowercase();
        if username.is_empty() || password.is_empty() {
            return Err(failed("empty Apple ID or password"));
        }
        self.lookup()?;
        // A successful device challenge requires a fresh SRP login. Bound this
        // transition to avoid indefinitely repeating account-side challenges.
        for round in 0..2 {
            let (spd, complete) = self.srp_login(&username, password)?;
            let auth = status(&complete).get("au").and_then(Value::as_str);
            let needs_2fa = auth == Some("trustedDeviceSecondaryAuth")
                || status(&complete).get("hsc").and_then(Value::as_i64) == Some(409);
            if needs_2fa {
                if round != 0 {
                    return Err(Error::new(
                        ErrorCode::TwoFactorFailed,
                        "Apple still requires 2FA after successful verification",
                    ));
                }
                self.two_factor(&spd, input)?;
                continue;
            }
            if auth.is_some_and(|a| a != "repair") {
                return Err(Error::new(
                    ErrorCode::TwoFactorFailed,
                    "account requires an unsupported additional authentication step; use trusted-device 2FA",
                ));
            }
            return self.app_token(&spd, password);
        }
        Err(failed("authentication did not complete"))
    }
    fn request(&mut self, mut request: Request) -> Result<Value> {
        endpoint(&request.url)?;
        request.max_body = MAX_BODY;
        request.headers.extend(self.anisette.headers()?.headers);
        request = request
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "text/x-xml-plist")
            .header("X-Apple-App-Info", APP)
            .header("X-Xcode-Version", "15.0 (15A240d)");
        let response = self.transport.send(&request).map_err(|_| {
            Error::new(
                ErrorCode::AppleTransportError,
                "Apple authentication transport failed",
            )
        })?;
        if !response.is_success() {
            return Err(failed(format!(
                "Apple authentication returned HTTP {}",
                response.status
            )));
        }
        if response.body.len() > MAX_BODY {
            return Err(failed("Apple authentication response too large"));
        }
        if response.body.is_empty()
            && request
                .headers
                .iter()
                .any(|(k, _)| k == "X-Apple-Identity-Token")
            && !request.headers.iter().any(|(k, _)| k == "security-code")
        {
            return Ok(Value::Dictionary(Dictionary::from_iter([(
                "ec",
                Value::from(0i64),
            )])));
        }
        plist::from_bytes(&response.body).map_err(|_| failed("invalid Apple authentication plist"))
    }
    fn lookup(&mut self) -> Result<()> {
        if self.urls.is_none() {
            let p = self.request(Request::get(LOOKUP))?;
            self.urls = Some(
                p.get("urls")
                    .and_then(Value::as_dict)
                    .cloned()
                    .ok_or_else(|| failed("GSA lookup missing urls"))?,
            );
        }
        Ok(())
    }
    fn url(&self, name: &str) -> Result<String> {
        let u = self
            .urls
            .as_ref()
            .and_then(|d| d.get(name))
            .and_then(Value::as_str)
            .ok_or_else(|| failed(format!("GSA lookup missing {name}")))?;
        endpoint(u)?;
        Ok(u.into())
    }
    fn cpd(&mut self) -> Result<Dictionary> {
        let mut d = Dictionary::from_iter([
            ("bootstrap", "true"),
            ("icscrec", "true"),
            ("loc", "en_US"),
            ("pbe", "false"),
            ("prkgen", "true"),
            ("svct", "iCloud"),
        ]);
        for (k, v) in self.anisette.headers()?.headers {
            d.insert(k, v);
        }
        Ok(d)
    }
    fn operation(&mut self, request: Dictionary, secrets: &[&str]) -> Result<Value> {
        let p = Value::Dictionary(Dictionary::from_iter([
            (
                "Header",
                Value::Dictionary(Dictionary::from_iter([("Version", "1.0.1")])),
            ),
            ("Request", Value::Dictionary(request)),
        ]));
        let url = self.url("gsService")?;
        let p = self.request(Request::post(url, p.to_xml()))?;
        let r = p
            .get("Response")
            .cloned()
            .ok_or_else(|| failed("GSA missing Response"))?;
        check(&r, secrets, ErrorCode::LoginFailed)?;
        Ok(r)
    }
    fn srp_login(&mut self, username: &str, password: &str) -> Result<(Value, Value)> {
        let srp = SrpClient::new().map_err(|_| failed("cannot initialize SRP"))?;
        let cpd = self.cpd()?;
        let init = Dictionary::from_iter([
            ("A2k", Value::Data(srp.public_ephemeral())),
            ("cpd", Value::Dictionary(cpd.clone())),
            ("o", Value::from("init")),
            ("ps", Value::Array(vec!["s2k".into(), "s2k_fo".into()])),
            ("u", Value::from(username)),
        ]);
        let r = self.operation(init, &[password])?;
        let protocol = Protocol::from_name(string(&r, "sp")?)
            .ok_or_else(|| failed("unsupported SRP password protocol"))?;
        let iterations = r
            .get("i")
            .and_then(Value::as_u64)
            .filter(|&i| i > 0 && i <= 1_000_000)
            .ok_or_else(|| failed("invalid SRP iteration count"))? as u32;
        let salt = data(&r, "s")?;
        let b = data(&r, "B")?;
        if salt.len() > 64 || b.len() > 256 {
            return Err(failed("invalid SRP challenge size"));
        }
        let c = r
            .get("c")
            .filter(|v| matches!(v, Value::String(_) | Value::Data(_)))
            .cloned()
            .ok_or_else(|| failed("missing SRP context"))?;
        let session = srp
            .process(username, password, protocol, salt, iterations, b)
            .map_err(|_| failed("invalid SRP challenge"))?;
        let complete = self.operation(
            Dictionary::from_iter([
                ("M1", Value::Data(session.m1.to_vec())),
                ("c", c),
                ("cpd", Value::Dictionary(cpd)),
                ("o", "complete".into()),
                ("u", username.into()),
            ]),
            &[password],
        )?;
        if !session.verify_server(data(&complete, "M2")?) {
            return Err(failed("SRP server proof mismatch"));
        }
        let (key, iv) = session.extra_data_key_iv();
        let raw = cbc::decrypt(&key, &iv, data(&complete, "spd")?)
            .map_err(|_| failed("cannot decrypt GSA session data"))?;
        let spd =
            plist::from_bytes(&raw).map_err(|_| failed("invalid decrypted GSA session data"))?;
        Ok((spd, complete))
    }
    fn two_factor_request(
        &mut self,
        spd: &Value,
        name: &str,
        verification: Option<&str>,
    ) -> Result<Value> {
        let identity = base64::encode(
            format!("{}:{}", string(spd, "adsid")?, string(spd, "GsIdmsToken")?).as_bytes(),
        );
        let mut request = Request::get(self.url(name)?).header("X-Apple-Identity-Token", &identity);
        if let Some(code) = verification {
            request = request.header("security-code", code);
        }
        self.request(request).map_err(|mut e| {
            if e.code != ErrorCode::AnisetteUnavailable && e.code != ErrorCode::AppleTransportError
            {
                e.code = ErrorCode::TwoFactorFailed;
            }
            e
        })
    }
    fn two_factor(
        &mut self,
        spd: &Value,
        input: &mut impl FnMut() -> Result<CodeInput>,
    ) -> Result<()> {
        let send = self.two_factor_request(spd, "trustedDeviceSecondaryAuth", None)?;
        check(
            &send,
            &[string(spd, "GsIdmsToken")?],
            ErrorCode::TwoFactorFailed,
        )?;
        loop {
            match input()? {
                CodeInput::Resend => {
                    let r = self.two_factor_request(spd, "trustedDeviceSecondaryAuth", None)?;
                    check(
                        &r,
                        &[string(spd, "GsIdmsToken")?],
                        ErrorCode::TwoFactorFailed,
                    )?;
                }
                CodeInput::Code(code_text) => {
                    if code_text.len() != 6 || !code_text.bytes().all(|b| b.is_ascii_digit()) {
                        continue;
                    }
                    let r = self.two_factor_request(spd, "validateCode", Some(&code_text))?;
                    if code(&r) == Some(-21669) {
                        continue;
                    }
                    check(
                        &r,
                        &[&code_text, string(spd, "GsIdmsToken")?],
                        ErrorCode::TwoFactorFailed,
                    )?;
                    return Ok(());
                }
            }
        }
    }
    fn app_token(&mut self, spd: &Value, password: &str) -> Result<Session> {
        let adsid = string(spd, "adsid")?;
        let idms = string(spd, "GsIdmsToken")?;
        let key = data(spd, "sk")?;
        if key.len() != 32 {
            return Err(failed("invalid app token key"));
        }
        let checksum = crypto::hmac_sha256(key, &[b"apptokens", adsid.as_bytes(), APP.as_bytes()]);
        let cpd = self.cpd()?;
        let r = self.operation(
            Dictionary::from_iter([
                ("app", Value::Array(vec![APP.into()])),
                ("c", Value::Data(data(spd, "c")?.to_vec())),
                ("checksum", Value::Data(checksum.to_vec())),
                ("cpd", Value::Dictionary(cpd)),
                ("o", "apptokens".into()),
                ("u", adsid.into()),
                ("t", idms.into()),
            ]),
            &[password, idms],
        )?;
        let token = decrypt_token(data(&r, "et")?, key)?;
        if token.get("status-code").and_then(Value::as_i64) != Some(200) {
            return Err(failed("Apple app token response was not successful"));
        }
        let token = token
            .get("t")
            .and_then(|v| v.get(APP))
            .ok_or_else(|| failed("missing Xcode app token"))?;
        Ok(Session {
            adsid: adsid.into(),
            token: string(token, "token")?.into(),
            expiry: token.get("expiry").and_then(Value::as_u64),
        })
    }
}
fn decrypt_token(et: &[u8], key: &[u8]) -> Result<Value> {
    if et.len() < 35 || &et[..3] != b"XYZ" {
        return Err(failed("invalid encrypted app token framing"));
    }
    let raw = gcm::decrypt(key, &et[3..19], &et[..3], &et[19..])
        .map_err(|_| failed("app token authentication failed"))?;
    plist::from_bytes(&raw).map_err(|_| failed("invalid decrypted app token plist"))
}
#[cfg(test)]
mod tests;
