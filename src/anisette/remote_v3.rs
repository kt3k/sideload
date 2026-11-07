//! SideStore anisette-v3 protocol: client info, WebSocket provisioning relay,
//! persisted ADI state, and fresh OTP headers. No Apple account credentials.
//!
//! Protocol references: nab138/isideload (MIT) and omnisette's published v3
//! exchange. This implementation uses the in-tree formats and blocking network
//! layers; remote responses and provisioning secrets are never logged.

use super::{AnisetteData, AnisetteProvider};
use crate::{
    Error, ErrorCode, Result, crypto,
    formats::{
        base64, date, json,
        plist::{self, Dictionary, Value},
    },
    net::{
        NetResult,
        http::{Client, Request, Response, Url},
        websocket::{Message, WebSocket},
    },
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_ADI: usize = 1024 * 1024;
fn unavailable(message: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::AnisetteUnavailable,
        format!("{message}; try another --anisette-server or use local ADI"),
    )
}
fn field<'a>(v: &'a json::Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(json::Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_BODY)
        .ok_or_else(|| unavailable(format!("anisette response has no valid {key}")))
}
fn header_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 8192 && !value.bytes().any(|b| b.is_ascii_control())
}
fn current_time() -> Result<String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable("system clock precedes Unix epoch"))?
        .as_secs();
    Ok(date::format_iso8601(
        i64::try_from(secs).map_err(|_| unavailable("invalid system clock"))?,
    ))
}

struct State {
    identifier: [u8; 16],
    adi_pb: Option<Vec<u8>>,
}
impl State {
    fn new() -> Result<Self> {
        let random = crypto::random_bytes(16)
            .map_err(|_| unavailable("cannot generate anisette identifier"))?;
        Ok(Self {
            identifier: random.try_into().unwrap(),
            adi_pb: None,
        })
    }
    fn device_id(&self) -> String {
        let h = crypto::hex(&self.identifier);
        format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    }
    fn local_user_id(&self) -> String {
        crypto::hex(&crypto::sha256(&self.identifier))
    }
    fn to_plist(&self) -> Vec<u8> {
        let mut d = Dictionary::new();
        d.insert("keychain_identifier", Value::Data(self.identifier.to_vec()));
        if let Some(pb) = &self.adi_pb {
            d.insert("adi_pb", Value::Data(pb.clone()));
        }
        Value::Dictionary(d).to_xml()
    }
    fn parse(raw: &[u8]) -> Result<Self> {
        let v = plist::from_bytes(raw).map_err(|_| unavailable("invalid anisette state plist"))?;
        let identifier = v
            .get("keychain_identifier")
            .and_then(Value::as_data)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| unavailable("invalid anisette state identifier"))?;
        let adi_pb = match v.get("adi_pb") {
            None => None,
            Some(Value::Data(b)) if !b.is_empty() && b.len() <= MAX_ADI => Some(b.clone()),
            _ => return Err(unavailable("invalid persisted ADI state")),
        };
        Ok(Self { identifier, adi_pb })
    }
}
struct ClientInfo {
    description: String,
    user_agent: String,
}
trait Session {
    fn recv(&mut self) -> NetResult<Message>;
    fn send(&mut self, text: &str) -> NetResult<()>;
    fn close(&mut self) -> NetResult<()>;
}
impl Session for WebSocket {
    fn recv(&mut self) -> NetResult<Message> {
        WebSocket::recv(self)
    }
    fn send(&mut self, text: &str) -> NetResult<()> {
        self.send_text(text)
    }
    fn close(&mut self) -> NetResult<()> {
        WebSocket::close(self)
    }
}
trait Transport {
    fn http(&mut self, request: &Request) -> NetResult<Response>;
    fn websocket(&mut self, url: &str) -> NetResult<Box<dyn Session>>;
}
struct Network(Client);
impl Transport for Network {
    fn http(&mut self, request: &Request) -> NetResult<Response> {
        self.0.send_without_redirects(request)
    }
    fn websocket(&mut self, url: &str) -> NetResult<Box<dyn Session>> {
        Ok(Box::new(WebSocket::connect(&self.0, url)?))
    }
}

/// A remote provider bound to one server and a per-server private state file.
/// The config directory is the Settings config_dir, not a per-run workdir.
/// Invalid saved state fails explicitly; remove its state.plist to reset.
pub struct RemoteV3 {
    server: String,
    state_path: PathBuf,
    state: Option<State>,
    info: Option<ClientInfo>,
    transport: Box<dyn Transport>,
}
impl std::fmt::Debug for RemoteV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteV3")
            .field("state_path", &self.state_path)
            .field(
                "provisioned",
                &self.state.as_ref().is_some_and(|s| s.adi_pb.is_some()),
            )
            .finish_non_exhaustive()
    }
}
impl RemoteV3 {
    pub fn new(server: &str, config_dir: &Path) -> Result<Self> {
        // gsa.apple.com chains to the Apple Root CA, which is not in the
        // Mozilla root set; Sideloader and isideload trust it explicitly too.
        let apple_root = [crate::sign::apple_certs::ROOT_CA.to_vec()];
        let client = Client::new(concat!("sideload/", env!("CARGO_PKG_VERSION")), &apple_root)
            .map_err(|_| unavailable("cannot initialize anisette TLS client"))?;
        Self::with_transport(server, config_dir, Box::new(Network(client)))
    }
    fn with_transport(
        server: &str,
        config_dir: &Path,
        transport: Box<dyn Transport>,
    ) -> Result<Self> {
        let u = Url::parse(server).map_err(|_| unavailable("invalid anisette server URL"))?;
        if server.contains(['?', '#']) {
            return Err(unavailable(
                "anisette base URL must not contain query or fragment",
            ));
        }
        let server = format!(
            "{}://{}{}",
            u.scheme(),
            u.authority(),
            u.path.trim_end_matches('/')
        );
        let name = crypto::hex(&crypto::sha256(server.as_bytes()));
        Ok(Self {
            server,
            state_path: config_dir.join("anisette").join(name).join("state.plist"),
            state: None,
            info: None,
            transport,
        })
    }
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
    fn http(&mut self, req: Request, stage: &str) -> Result<Response> {
        let response = self
            .transport
            .http(&req)
            .map_err(|_| unavailable(format!("{stage}: transport failed")))?;
        if !response.is_success() {
            return Err(unavailable(format!("{stage}: HTTP {}", response.status)));
        }
        if response.body.len() > req.max_body {
            return Err(unavailable(format!("{stage}: response too large")));
        }
        Ok(response)
    }
    fn json(&mut self, req: Request, stage: &str) -> Result<json::Value> {
        let response = self.http(req.max_body(MAX_BODY), stage)?;
        let text = std::str::from_utf8(&response.body)
            .map_err(|_| unavailable(format!("{stage}: invalid UTF-8")))?;
        json::parse(text).map_err(|_| unavailable(format!("{stage}: invalid JSON")))
    }
    fn prepare(&mut self) -> Result<()> {
        if self.info.is_none() {
            let info = self.json(
                Request::get(format!("{}/v3/client_info", self.server)),
                "client_info",
            )?;
            let description = field(&info, "client_info")?.to_owned();
            let user_agent = field(&info, "user_agent")?.to_owned();
            if !header_value(&description) || !header_value(&user_agent) {
                return Err(unavailable("invalid client_info headers"));
            }
            self.info = Some(ClientInfo {
                description,
                user_agent,
            });
        }
        if self.state.is_none() {
            self.state_directories(false)?;
            self.state = Some(match fs::symlink_metadata(&self.state_path) {
                Ok(m) if m.is_file() && !m.file_type().is_symlink() => {
                    if m.len() > MAX_BODY as u64 {
                        return Err(unavailable("saved anisette state is too large"));
                    }
                    let mut raw = Vec::new();
                    fs::File::open(&self.state_path)
                        .and_then(|f| f.take(MAX_BODY as u64 + 1).read_to_end(&mut raw))
                        .map_err(|_| unavailable("cannot read anisette state"))?;
                    if raw.len() > MAX_BODY {
                        return Err(unavailable("saved anisette state is too large"));
                    }
                    State::parse(&raw)?
                }
                Ok(_) => return Err(unavailable("anisette state is not a regular file")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::new()?,
                Err(_) => return Err(unavailable("cannot inspect anisette state")),
            });
        }
        Ok(())
    }
    fn state_directories(&self, create: bool) -> Result<()> {
        let parent = self.state_path.parent().unwrap();
        if create {
            fs::create_dir_all(parent.parent().unwrap().parent().unwrap())
                .map_err(|_| unavailable("cannot create config directory"))?;
        }
        for dir in [parent.parent().unwrap(), parent] {
            match fs::symlink_metadata(dir) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => {
                    return Err(unavailable(
                        "anisette state directory is not a real directory",
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => continue,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let builder = fs::DirBuilder::new();
                    #[cfg(unix)]
                    let mut builder = builder;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        builder.mode(0o700);
                    }
                    builder
                        .create(dir)
                        .map_err(|_| unavailable("cannot create anisette state directory"))?;
                }
                Err(_) => return Err(unavailable("cannot inspect anisette state directory")),
            }
            #[cfg(unix)]
            if create {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| unavailable("cannot protect anisette state directory"))?;
            }
        }
        Ok(())
    }
    fn save(&self) -> Result<()> {
        let parent = self.state_path.parent().unwrap();
        self.state_directories(true)?;
        if fs::symlink_metadata(&self.state_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(unavailable("symlink anisette state is unsupported"));
        }
        let suffix = crypto::hex(
            &crypto::random_bytes(8)
                .map_err(|_| unavailable("cannot create state temporary file"))?,
        );
        let temp = parent.join(format!(".state-{suffix}"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            let mut f = options.open(&temp)?;
            f.write_all(&self.state.as_ref().unwrap().to_plist())?;
            f.sync_all()?;
            fs::rename(&temp, &self.state_path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
            return Err(unavailable("cannot persist anisette state"));
        }
        Ok(())
    }
    fn apple_request(&self, mut req: Request) -> Result<Request> {
        let state = self.state.as_ref().unwrap();
        let info = self.info.as_ref().unwrap();
        for (k, v) in [
            ("X-Mme-Client-Info", info.description.clone()),
            ("User-Agent", info.user_agent.clone()),
            ("Content-Type", "text/x-xml-plist".into()),
            ("X-Apple-I-MD-LU", state.local_user_id()),
            ("X-Mme-Device-Id", state.device_id()),
            ("X-Apple-I-Client-Time", current_time()?),
            ("X-Apple-I-TimeZone", "UTC".into()),
            ("X-Apple-Locale", "en_US".into()),
        ] {
            req.headers.push((k.into(), v));
        }
        Ok(req.max_body(MAX_BODY))
    }
    fn apple_plist(&mut self, req: Request) -> Result<Value> {
        let req = self.apple_request(req)?;
        let resp = self.http(req, "Apple provisioning")?;
        plist::from_bytes(&resp.body).map_err(|_| unavailable("invalid Apple provisioning plist"))
    }
    fn apple_endpoint(value: Option<&Value>) -> Result<String> {
        let url = value
            .and_then(Value::as_str)
            .ok_or_else(|| unavailable("lookup missing provisioning URL"))?;
        let u = Url::parse(url).map_err(|_| unavailable("invalid Apple provisioning URL"))?;
        if !u.tls || u.port != 443 || !(u.host == "apple.com" || u.host.ends_with(".apple.com")) {
            return Err(unavailable("lookup returned a non-Apple HTTPS endpoint"));
        }
        Ok(url.into())
    }
    fn provision(&mut self) -> Result<()> {
        let lookup = self.apple_plist(Request::get(LOOKUP))?;
        let urls = lookup
            .get("urls")
            .and_then(Value::as_dict)
            .ok_or_else(|| unavailable("Apple lookup has no urls dictionary"))?;
        let start = Self::apple_endpoint(urls.get("midStartProvisioning"))?;
        let finish = Self::apple_endpoint(urls.get("midFinishProvisioning"))?;
        let url = self
            .server
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1)
            + "/v3/provisioning_session";
        let mut ws = self
            .transport
            .websocket(&url)
            .map_err(|_| unavailable("cannot open provisioning WebSocket"))?;
        let mut stage = 0;
        loop {
            let text = match ws
                .recv()
                .map_err(|_| unavailable("provisioning WebSocket failed"))?
            {
                Message::Text(t) => t,
                Message::Close => {
                    return Err(unavailable("provisioning socket closed before success"));
                }
            };
            if text.len() > MAX_BODY {
                return Err(unavailable("provisioning message too large"));
            }
            let msg = json::parse(&text).map_err(|_| unavailable("invalid provisioning JSON"))?;
            let response = match (stage, field(&msg, "result")?) {
                (0, "GiveIdentifier") => json::Value::object([(
                    "identifier",
                    base64::encode(&self.state.as_ref().unwrap().identifier).into(),
                )]),
                (1, "GiveStartProvisioningData") => {
                    let p = self.apple_plist(Request::post(&start, provision_body(None)))?;
                    json::Value::object([("spim", apple_field(&p, "spim")?.into())])
                }
                (2, "GiveEndProvisioningData") => {
                    let cpim = field(&msg, "cpim")?;
                    valid_base64(cpim)?;
                    let p = self.apple_plist(Request::post(&finish, provision_body(Some(cpim))))?;
                    json::Value::object([
                        ("ptm", apple_field(&p, "ptm")?.into()),
                        ("tk", apple_field(&p, "tk")?.into()),
                    ])
                }
                (3, "ProvisioningSuccess") => {
                    let pb = valid_base64(field(&msg, "adi_pb")?)?;
                    if pb.len() > MAX_ADI {
                        return Err(unavailable("ADI state too large"));
                    }
                    self.state.as_mut().unwrap().adi_pb = Some(pb);
                    self.save()?;
                    let _ = ws.close();
                    return Ok(());
                }
                (_, "Timeout") => return Err(unavailable("anisette provisioning timed out")),
                (_, "InvalidIdentifier" | "StartProvisioningError" | "EndProvisioningError") => {
                    return Err(unavailable("anisette server rejected provisioning"));
                }
                _ => return Err(unavailable("unexpected provisioning message or order")),
            };
            ws.send(&response.to_string())
                .map_err(|_| unavailable("cannot send provisioning response"))?;
            stage += 1;
        }
    }
    fn fetch(&mut self) -> Result<Option<AnisetteData>> {
        let state = self.state.as_ref().unwrap();
        let body = json::Value::object([
            ("identifier", base64::encode(&state.identifier).into()),
            (
                "adi_pb",
                base64::encode(state.adi_pb.as_ref().unwrap()).into(),
            ),
        ])
        .to_string()
        .into_bytes();
        let reply = self.json(
            Request::post(format!("{}/v3/get_headers", self.server), body)
                .header("Content-Type", "application/json"),
            "get_headers",
        )?;
        match field(&reply, "result")? {
            "GetHeadersError"
                if reply
                    .get("message")
                    .and_then(json::Value::as_str)
                    .is_some_and(|s| s.contains("-45061")) =>
            {
                return Ok(None);
            }
            "Headers" => {}
            _ => return Err(unavailable("anisette server did not return headers")),
        }
        let md = field(&reply, "X-Apple-I-MD")?;
        let machine = field(&reply, "X-Apple-I-MD-M")?;
        let routing = field(&reply, "X-Apple-I-MD-RINFO")?;
        valid_base64(md)?;
        valid_base64(machine)?;
        if !header_value(md)
            || !header_value(machine)
            || !header_value(routing)
            || routing.parse::<u64>().is_err()
        {
            return Err(unavailable("invalid anisette header values"));
        }
        let state = self.state.as_ref().unwrap();
        Ok(Some(AnisetteData {
            headers: vec![
                ("X-Apple-I-MD".into(), md.into()),
                ("X-Apple-I-MD-M".into(), machine.into()),
                ("X-Apple-I-MD-RINFO".into(), routing.into()),
                ("X-Apple-I-MD-LU".into(), state.local_user_id()),
                ("X-Mme-Device-Id".into(), state.device_id()),
                (
                    "X-Mme-Client-Info".into(),
                    self.info.as_ref().unwrap().description.clone(),
                ),
                // GSA expects the User-Agent that matches X-Mme-Client-Info.
                (
                    "User-Agent".into(),
                    self.info.as_ref().unwrap().user_agent.clone(),
                ),
                ("X-Apple-I-Client-Time".into(), current_time()?),
                ("X-Apple-I-TimeZone".into(), "UTC".into()),
                ("X-Apple-Locale".into(), "en_US".into()),
                ("X-Apple-I-SRL-NO".into(), "0".into()),
            ],
        }))
    }
}
impl AnisetteProvider for RemoteV3 {
    fn headers(&mut self) -> Result<AnisetteData> {
        self.prepare()?;
        if self.state.as_ref().unwrap().adi_pb.is_none() {
            self.provision()?;
        }
        if let Some(headers) = self.fetch()? {
            return Ok(headers);
        }
        // ADI was invalidated upstream: one bounded reprovision using the same
        // device identity, with no recursive or unbounded retry.
        self.state.as_mut().unwrap().adi_pb = None;
        self.save()?;
        self.provision()?;
        self.fetch()?
            .ok_or_else(|| unavailable("server still reports unprovisioned ADI after one reset"))
    }
}
fn valid_base64(s: &str) -> Result<Vec<u8>> {
    if s.len() > MAX_BODY {
        return Err(unavailable("provisioning data too large"));
    }
    base64::decode(s)
        .ok()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| unavailable("invalid base64 provisioning data"))
}
fn provision_body(cpim: Option<&str>) -> Vec<u8> {
    let mut request = Dictionary::new();
    if let Some(cpim) = cpim {
        request.insert("cpim", cpim);
    }
    Value::Dictionary(Dictionary::from_iter([
        ("Header", Value::Dictionary(Dictionary::new())),
        ("Request", Value::Dictionary(request)),
    ]))
    .to_xml()
}
fn apple_field<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    let r = p
        .get("Response")
        .and_then(Value::as_dict)
        .ok_or_else(|| unavailable("Apple provisioning response missing Response"))?;
    if r.get("Status")
        .and_then(|s| s.get("ec"))
        .and_then(Value::as_integer)
        .is_some_and(|ec| ec != 0)
    {
        return Err(unavailable("Apple rejected provisioning"));
    }
    let s = r
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable(format!("Apple provisioning response missing {key}")))?;
    valid_base64(s)?;
    Ok(s)
}

#[cfg(test)]
mod tests;
