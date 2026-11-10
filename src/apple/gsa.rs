//! GrandSlam SRP authentication, trusted-device 2FA, and Xcode app tokens.
//! Sessions remain in memory; passwords, proofs, SPD, and tokens are not logged.
use super::{Https, Transport, description, endpoint};
use crate::{
    Error, ErrorCode, Result,
    anisette::{AnisetteData, AnisetteProvider},
    credentials::{CodeInput, Credentials},
    crypto::{
        self, cbc, gcm,
        srp::{Protocol, SrpClient},
    },
    formats::{
        base64, json,
        plist::{self, Dictionary, Value},
    },
    net::http::{Request, Response},
};
const LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const APP: &str = "com.apple.gs.xcode.auth";
const MAX_BODY: usize = 4 * 1024 * 1024;

/// Encode provisioning metadata with plist types, independently of HTTP's
/// string-only representation. Shared with the password-free SRP-init probe.
pub fn client_provisioning_data(data: &AnisetteData) -> Result<Dictionary> {
    let mut d = Dictionary::from_iter([
        ("bootstrap", Value::Boolean(true)),
        ("icscrec", Value::Boolean(true)),
        ("loc", Value::from("en_US")),
        ("pbe", Value::Boolean(false)),
        ("prkgen", Value::Boolean(true)),
        ("svct", Value::from("iCloud")),
    ]);
    for (key, value) in &data.headers {
        if key.eq_ignore_ascii_case("X-Apple-I-MD-RINFO") {
            let routing = value.parse::<u64>().map_err(|_| {
                Error::new(
                    ErrorCode::AnisetteUnavailable,
                    "invalid anisette routing information",
                )
            })?;
            d.insert("X-Apple-I-MD-RINFO", Value::from(routing));
        } else {
            d.insert(key.clone(), value.clone());
        }
    }
    Ok(d)
}
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
    identity: Option<Vec<(String, String)>>,
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
            identity: None,
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
        self.identity = None;
        self.lookup()?;
        // A successful device challenge requires a fresh SRP login. Bound this
        // transition to avoid indefinitely repeating account-side challenges.
        for round in 0..2 {
            let (spd, complete) = self.srp_login(&username, password)?;
            let auth = status(&complete).get("au").and_then(Value::as_str);
            let needs_2fa = auth == Some("trustedDeviceSecondaryAuth")
                || auth == Some("secondaryAuth")
                || status(&complete).get("hsc").and_then(Value::as_i64) == Some(409);
            if needs_2fa {
                if round != 0 {
                    return Err(Error::new(
                        ErrorCode::TwoFactorFailed,
                        "Apple still requires 2FA after successful verification",
                    ));
                }
                self.two_factor(&spd, input, auth.is_none(), auth == Some("secondaryAuth"))?;
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
    fn pin_identity(&mut self, data: &AnisetteData) -> Result<()> {
        let mut identity = Vec::new();
        for key in ["X-Mme-Device-Id", "X-Mme-Client-Info", "User-Agent"] {
            if let Some((_, value)) = data
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(key))
            {
                identity.push((key.to_owned(), value.clone()));
            }
        }
        if let Some(saved) = &self.identity {
            if saved != &identity {
                return Err(Error::new(
                    ErrorCode::AnisetteUnavailable,
                    "Anisette identity changed during sign-in; use a provider with a persistent identity",
                ));
            }
        } else {
            self.identity = Some(identity);
        }
        Ok(())
    }
    fn fresh_anisette(&mut self) -> Result<AnisetteData> {
        let data = self.anisette.headers()?;
        self.pin_identity(&data)?;
        Ok(data)
    }
    fn response(&mut self, mut request: Request, data: AnisetteData) -> Result<Response> {
        endpoint(&request.url)?;
        request.max_body = MAX_BODY;
        request.headers.extend(data.headers);
        for (key, value) in [
            ("Content-Type", "text/x-xml-plist"),
            ("Accept", "text/x-xml-plist"),
            ("X-Apple-App-Info", APP),
            ("X-Xcode-Version", "15.0 (15A240d)"),
            ("Connection", "close"),
        ] {
            if !request
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(key))
            {
                request = request.header(key, value);
            }
        }
        let response = self.transport.send(&request).map_err(|_| {
            Error::new(
                ErrorCode::AppleTransportError,
                "Apple authentication transport failed",
            )
        })?;
        if response.body.len() > MAX_BODY {
            return Err(failed("Apple authentication response too large"));
        }
        Ok(response)
    }
    fn plist_response(&mut self, request: Request, data: AnisetteData) -> Result<Value> {
        let empty_ok = request
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Apple-Identity-Token"))
            && !request
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("security-code"));
        let response = self.response(request, data)?;
        if !response.is_success() {
            super::debug_response("GSA", response.status, &response.body, &[]);
            return Err(failed(format!(
                "Apple authentication returned HTTP {}",
                response.status
            )));
        }
        if response.body.is_empty() && empty_ok {
            return Ok(Value::Dictionary(Dictionary::from_iter([(
                "ec",
                Value::from(0i64),
            )])));
        }
        let mut value = plist::from_bytes(&response.body)
            .map_err(|_| failed("invalid Apple authentication plist"))?;
        if let Some(sim) = response.header("X-Apple-I-MD-DATA") {
            if let Value::Dictionary(d) = &mut value {
                d.insert("X-Apple-I-MD-DATA", sim);
            }
        }
        Ok(value)
    }
    fn request(&mut self, request: Request) -> Result<Value> {
        let data = self.fresh_anisette()?;
        self.plist_response(request, data)
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
    fn operation(&mut self, mut request: Dictionary, secrets: &[&str]) -> Result<Value> {
        let is_init = request.get("o").and_then(Value::as_str) == Some("init");
        let mut synchronized = None;
        for attempt in 0..2 {
            let data = match synchronized.take() {
                Some(data) => data,
                None => self.fresh_anisette()?,
            };
            request.insert("cpd", Value::Dictionary(client_provisioning_data(&data)?));
            let envelope = Value::Dictionary(Dictionary::from_iter([
                (
                    "Header",
                    Value::Dictionary(Dictionary::from_iter([("Version", "1.0.1")])),
                ),
                ("Request", Value::Dictionary(request.clone())),
            ]));
            let url = self.url("gsService")?;
            let p = self.plist_response(Request::post(url, envelope.to_xml()), data)?;
            let r = p
                .get("Response")
                .cloned()
                .ok_or_else(|| failed("GSA missing Response"))?;
            if status(&r).get("hsc").and_then(Value::as_i64) == Some(434) {
                if !is_init || attempt != 0 {
                    return Err(Error::new(
                        ErrorCode::AnisetteUnavailable,
                        "Apple still requires Anisette resynchronization; restart sign-in",
                    ));
                }
                let sim = r
                    .get("X-Apple-I-MD-DATA")
                    .or_else(|| p.get("X-Apple-I-MD-DATA"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && s.len() <= MAX_BODY)
                    .ok_or_else(|| {
                        failed("Apple resynchronization response has no valid machine data")
                    })?;
                let fresh = self.anisette.resync(sim)?;
                self.pin_identity(&fresh)?;
                synchronized = Some(fresh);
                continue;
            }
            check(&r, secrets, ErrorCode::LoginFailed)?;
            return Ok(r);
        }
        Err(failed("Anisette resynchronization did not complete"))
    }
    fn srp_login(&mut self, username: &str, password: &str) -> Result<(Value, Value)> {
        let srp = SrpClient::new().map_err(|_| failed("cannot initialize SRP"))?;
        let init = Dictionary::from_iter([
            ("A2k", Value::Data(srp.public_ephemeral())),
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
    fn json_auth(
        &mut self,
        spd: &Value,
        method: &'static str,
        path: &str,
        body: Option<json::Value>,
    ) -> Result<json::Value> {
        let identity = base64::encode(
            format!("{}:{}", string(spd, "adsid")?, string(spd, "GsIdmsToken")?).as_bytes(),
        );
        let mut request = Request::get(format!("https://gsa.apple.com/auth{path}"))
            .header("X-Apple-Identity-Token", &identity)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        request.method = method;
        if let Some(body) = body {
            request.body = body.to_string().into_bytes();
        }
        let data = self.fresh_anisette()?;
        let response = self.response(request, data)?;
        let value = if response.body.is_empty() {
            Some(json::Value::object::<&str>([]))
        } else {
            std::str::from_utf8(&response.body)
                .ok()
                .and_then(|s| json::parse(s).ok())
        };
        let error_code = value
            .as_ref()
            .and_then(|v| {
                v.get("ec").or_else(|| {
                    v.get("serviceErrors")
                        .and_then(json::Value::as_array)
                        .and_then(|a| a.first())
                        .and_then(|e| e.get("code"))
                })
            })
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .or_else(|| v.as_f64().map(|n| n as i64))
            });
        if error_code == Some(-21669) {
            return Ok(json::Value::object([("ec", json::Value::from(-21669f64))]));
        }
        if !response.is_success() {
            return Err(Error::new(
                ErrorCode::TwoFactorFailed,
                format!("Apple verification returned HTTP {}", response.status),
            ));
        }
        let value = value.ok_or_else(|| {
            Error::new(
                ErrorCode::TwoFactorFailed,
                "invalid Apple verification JSON",
            )
        })?;
        if error_code.is_some_and(|c| c != 0)
            || value
                .get("serviceErrors")
                .and_then(json::Value::as_array)
                .is_some_and(|a| !a.is_empty())
        {
            return Err(Error::new(
                ErrorCode::TwoFactorFailed,
                "Apple rejected the verification request",
            ));
        }
        Ok(value)
    }
    fn phone_id(info: &json::Value) -> Option<u32> {
        fn id(v: &json::Value) -> Option<u32> {
            v.get("id")?
                .as_f64()
                .filter(|n| n.is_finite() && *n > 0.0 && *n <= u32::MAX as f64 && n.fract() == 0.0)
                .map(|n| n as u32)
        }
        info.get("trustedPhoneNumber").and_then(id).or_else(|| {
            info.get("trustedPhoneNumbers")?
                .as_array()?
                .iter()
                .find_map(id)
        })
    }
    fn sms_request(&mut self, spd: &Value, phone: u32, code_text: Option<&str>) -> Result<bool> {
        let mut fields = vec![
            (
                "phoneNumber",
                json::Value::object([("id", json::Value::from(phone as f64))]),
            ),
            ("mode", json::Value::from("sms")),
        ];
        if let Some(code) = code_text {
            fields.push((
                "securityCode",
                json::Value::object([("code", json::Value::from(code))]),
            ));
        }
        let (method, path) = if code_text.is_some() {
            ("POST", "/verify/phone/securitycode")
        } else {
            ("PUT", "/verify/phone")
        };
        let reply = self.json_auth(spd, method, path, Some(json::Value::object(fields)))?;
        let accepted = reply.get("ec").and_then(json::Value::as_f64) != Some(-21669.0);
        if !accepted && code_text.is_none() {
            return Err(Error::new(
                ErrorCode::TwoFactorFailed,
                "Apple could not send an SMS code",
            ));
        }
        Ok(accepted)
    }
    fn two_factor(
        &mut self,
        spd: &Value,
        input: &mut impl FnMut() -> Result<CodeInput>,
        already_sent: bool,
        prefer_sms: bool,
    ) -> Result<()> {
        let info = match self.json_auth(spd, "GET", "", None) {
            Ok(info) => Some(info),
            Err(e) if e.code == ErrorCode::AnisetteUnavailable || prefer_sms => return Err(e),
            Err(_) => None, // Some providers cannot fetch metadata; trusted-device codes still work.
        };
        let sms = prefer_sms
            || info
                .as_ref()
                .and_then(|v| v.get("noTrustedDevices"))
                .and_then(json::Value::as_bool)
                == Some(true);
        let phone = if sms {
            Some(info.as_ref().and_then(Self::phone_id).ok_or_else(|| {
                Error::new(
                    ErrorCode::TwoFactorFailed,
                    "Apple did not return a usable trusted phone number",
                )
            })?)
        } else {
            None
        };
        if !already_sent {
            if let Some(phone) = phone {
                self.sms_request(spd, phone, None)?;
            } else {
                let reply = self.two_factor_request(spd, "trustedDeviceSecondaryAuth", None)?;
                check(
                    &reply,
                    &[string(spd, "GsIdmsToken")?],
                    ErrorCode::TwoFactorFailed,
                )?;
            }
        }
        loop {
            match input()? {
                CodeInput::Resend => {
                    if let Some(phone) = phone {
                        self.sms_request(spd, phone, None)?;
                    } else {
                        let r = self.two_factor_request(spd, "trustedDeviceSecondaryAuth", None)?;
                        check(
                            &r,
                            &[string(spd, "GsIdmsToken")?],
                            ErrorCode::TwoFactorFailed,
                        )?;
                    }
                }
                CodeInput::Code(code_text) => {
                    if code_text.len() != 6 || !code_text.bytes().all(|b| b.is_ascii_digit()) {
                        continue;
                    }
                    if let Some(phone) = phone {
                        if !self.sms_request(spd, phone, Some(&code_text))? {
                            continue;
                        }
                    } else {
                        let r = self.two_factor_request(spd, "validateCode", Some(&code_text))?;
                        if code(&r) == Some(-21669) {
                            continue;
                        }
                        check(
                            &r,
                            &[&code_text, string(spd, "GsIdmsToken")?],
                            ErrorCode::TwoFactorFailed,
                        )?;
                    }
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
        let r = self.operation(
            Dictionary::from_iter([
                ("app", Value::Array(vec![APP.into()])),
                ("c", Value::Data(data(spd, "c")?.to_vec())),
                ("checksum", Value::Data(checksum.to_vec())),
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
