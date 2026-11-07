//! Stable local identity and Apple provisioning exchange. Native ABI is isolated
//! behind Engine so provisioning can be tested without executing vendor code.
use super::AdiResult;
use crate::{
    Error, ErrorCode, Result,
    anisette::AnisetteData,
    apple::{Transport, endpoint},
    crypto,
    formats::{
        base64, date, json,
        plist::{self, Dictionary, Value},
    },
    net::http::Request,
};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn error(message: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::AnisetteUnavailable,
        format!("local ADI: {message}; use --anisette-server to switch backends"),
    )
}
pub trait Engine {
    fn is_provisioned(&mut self) -> AdiResult<bool>;
    fn start(&mut self, spim: &[u8]) -> AdiResult<(Vec<u8>, u32)>;
    fn finish(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> AdiResult<()>;
    fn destroy(&mut self, session: u32);
    fn otp(&mut self) -> AdiResult<(Vec<u8>, Vec<u8>)>;
}
pub struct Identity {
    pub description: String,
    pub device_id: String,
    pub android_id: String,
    pub local_user: String,
}
impl Identity {
    fn parse(raw: &str) -> Result<Self> {
        let p = json::parse(raw).map_err(|_| error("invalid device.json"))?;
        let get = |k| {
            p.get(k)
                .and_then(json::Value::as_str)
                .filter(|s| !s.is_empty() && s.len() < 8192 && !s.chars().any(char::is_control))
                .map(str::to_owned)
                .ok_or_else(|| error("invalid device identity field"))
        };
        let identity = Self {
            description: get("serverFriendlyDescription")?,
            device_id: get("uniqueDeviceIdentifier")?,
            android_id: get("adiIdentifier")?,
            local_user: get("localUserUUID")?,
        };
        if identity.android_id.len() != 16
            || !identity.android_id.bytes().all(|b| b.is_ascii_hexdigit())
            || identity.local_user.len() != 64
            || !identity.local_user.bytes().all(|b| b.is_ascii_hexdigit())
            || identity.device_id.len() != 36
            || !identity
                .device_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(error("invalid local device identity"));
        }
        Ok(identity)
    }
    pub fn load(config: &Path) -> Result<Self> {
        let path = config.join("device.json");
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() && m.len() <= 65536 => {
                let mut s = String::new();
                fs::File::open(&path)
                    .and_then(|f| f.take(65537).read_to_string(&mut s))
                    .map_err(|_| error("cannot read device identity"))?;
                return Self::parse(&s);
            }
            Ok(_) => return Err(error("device identity is not a regular bounded file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error("cannot inspect device identity")),
        }
        let random = crypto::random_bytes(16).map_err(|_| error("cannot generate device UUID"))?;
        let h = crypto::hex(&random).to_uppercase();
        let device_id = format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        );
        let identity = Self {
            description:
                "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                    .into(),
            device_id,
            android_id: crypto::hex(
                &crypto::random_bytes(8)
                    .map_err(|_| error("cannot generate Android identifier"))?,
            ),
            local_user: crypto::hex(
                &crypto::random_bytes(32)
                    .map_err(|_| error("cannot generate local user identifier"))?,
            )
            .to_uppercase(),
        };
        let p = json::Value::object([
            (
                "serverFriendlyDescription",
                identity.description.clone().into(),
            ),
            ("uniqueDeviceIdentifier", identity.device_id.clone().into()),
            ("adiIdentifier", identity.android_id.clone().into()),
            ("localUserUUID", identity.local_user.clone().into()),
        ]);
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(config)
            .map_err(|_| error("cannot create ADI config directory"))?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&path).map_err(|_| {
            error("cannot create local identity (another process may be initializing it)")
        })?;
        f.write_all(p.to_string().as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|_| error("cannot save device identity"))?;
        Ok(identity)
    }
    fn headers(&self) -> Result<Vec<(String, String)>> {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error("invalid system clock"))?
            .as_secs();
        Ok(vec![
            ("X-Mme-Client-Info".into(), self.description.clone()),
            ("X-Mme-Device-Id".into(), self.device_id.clone()),
            ("X-Apple-I-MD-LU".into(), self.local_user.clone()),
            (
                "X-Apple-I-Client-Time".into(),
                date::format_iso8601(secs as i64),
            ),
            ("X-Apple-I-TimeZone".into(), "UTC".into()),
            ("X-Apple-Locale".into(), "en_US".into()),
            ("X-Apple-I-SRL-NO".into(), "0".into()),
            (
                "User-Agent".into(),
                "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0".into(),
            ),
        ])
    }
}
fn request(identity: &Identity, transport: &mut dyn Transport, mut r: Request) -> Result<Value> {
    endpoint(&r.url)?;
    r.headers.extend(identity.headers()?);
    r = r
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Apple-Client-App-Name", "Setup")
        .max_body(4 * 1024 * 1024);
    let p = transport
        .send(&r)
        .map_err(|_| error("Apple provisioning transport failed"))?;
    if !p.is_success() || p.body.len() > r.max_body {
        return Err(error(format!(
            "Apple provisioning returned HTTP {} or oversized response",
            p.status
        )));
    }
    plist::from_bytes(&p.body).map_err(|_| error("invalid Apple provisioning plist"))
}
fn body(cpim: Option<&[u8]>) -> Vec<u8> {
    let mut r = Dictionary::new();
    if let Some(cpim) = cpim {
        r.insert("cpim", base64::encode(cpim));
    }
    Value::Dictionary(Dictionary::from_iter([
        ("Header", Value::Dictionary(Dictionary::new())),
        ("Request", Value::Dictionary(r)),
    ]))
    .to_xml()
}
fn decoded(p: &Value, k: &str) -> Result<Vec<u8>> {
    let r = p
        .get("Response")
        .ok_or_else(|| error("missing provisioning Response"))?;
    if r.get("Status")
        .and_then(|v| v.get("ec"))
        .and_then(Value::as_i64)
        .is_some_and(|c| c != 0)
    {
        return Err(error("Apple rejected local provisioning"));
    }
    let s = r
        .get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| error(format!("missing provisioning {k}")))?;
    base64::decode(s)
        .ok()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| error("invalid provisioning base64"))
}
pub fn headers(
    identity: &Identity,
    engine: &mut dyn Engine,
    transport: &mut dyn Transport,
) -> Result<AnisetteData> {
    if !engine.is_provisioned().map_err(error)? {
        let p = request(
            identity,
            transport,
            Request::get("https://gsa.apple.com/grandslam/GsService2/lookup"),
        )?;
        let urls = p
            .get("urls")
            .and_then(Value::as_dict)
            .ok_or_else(|| error("Apple lookup missing urls"))?;
        let get = |key| {
            let u = urls
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| error("Apple lookup missing provisioning endpoint"))?;
            endpoint(u)?;
            Ok::<_, Error>(u)
        };
        let start = get("midStartProvisioning")?;
        let end = get("midFinishProvisioning")?;
        let p = request(identity, transport, Request::post(start, body(None)))?;
        let (cpim, session) = engine.start(&decoded(&p, "spim")?).map_err(error)?;
        let result = (|| {
            let p = request(identity, transport, Request::post(end, body(Some(&cpim))))?;
            engine
                .finish(session, &decoded(&p, "ptm")?, &decoded(&p, "tk")?)
                .map_err(error)
        })();
        if result.is_err() {
            engine.destroy(session);
        }
        result?;
        if !engine.is_provisioned().map_err(error)? {
            return Err(error("ADI did not persist provisioning"));
        }
    }
    let (mid, otp) = engine.otp().map_err(error)?;
    if mid.is_empty() || otp.is_empty() {
        return Err(error("empty OTP result"));
    }
    let mut headers = identity.headers()?;
    headers.extend([
        ("X-Apple-I-MD".into(), base64::encode(&otp)),
        ("X-Apple-I-MD-M".into(), base64::encode(&mid)),
        ("X-Apple-I-MD-RINFO".into(), "17106176".into()),
    ]);
    Ok(AnisetteData { headers })
}
#[cfg(test)]
mod tests;
