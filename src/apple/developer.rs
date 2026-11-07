//! Apple Developer Services QH65B2 operations (iOS, SPEC 9.4).
//! Mutations use explicit identifiers and never retry automatically.
use super::{
    Https, Transport, description,
    gsa::{Gsa, Session},
};
use crate::{
    Error, ErrorCode, Result,
    anisette::AnisetteProvider,
    crypto,
    formats::{
        der,
        plist::{self, Dictionary, Value},
    },
    net::http::Request,
};
const BASE: &str = "https://developerservices2.apple.com/services/QH65B2/";
/// Apple's feature key that enables App Groups on an App ID.
pub const APP_GROUP_FEATURE: &str = "APG3427HIY";
fn malformed(field: &str) -> Error {
    Error::new(
        ErrorCode::AppleApiError,
        format!("invalid Developer Services field {field}"),
    )
}
fn string(v: &Value, k: &str) -> Result<String> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| malformed(k))
}
fn optional(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}
fn date(v: &Value, k: &str) -> Option<f64> {
    match v.get(k) {
        Some(Value::Date(t)) => Some(*t),
        Some(Value::String(s)) => crate::formats::date::parse_iso8601(s)
            .ok()
            .map(|t| t as f64),
        _ => None,
    }
}
fn team(id: &str) -> Dictionary {
    Dictionary::from_iter([("teamId", id)])
}
fn with_id(team_id: &str, key: &str, id: &str) -> Dictionary {
    let mut d = team(team_id);
    d.insert(key, id);
    d
}
fn uuid() -> Result<String> {
    let mut b = crypto::random_bytes(16).map_err(|_| {
        Error::new(
            ErrorCode::InternalError,
            "cannot create Apple request identifier",
        )
    })?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = crypto::hex(&b).to_uppercase();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
#[derive(Debug, Clone, PartialEq)]
pub struct Team {
    pub team_id: String,
    pub name: Option<String>,
    pub kind: Option<String>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub device_id: String,
    pub udid: String,
    pub name: Option<String>,
    pub status: Option<String>,
}
#[derive(Clone, PartialEq)]
pub struct Certificate {
    pub platform: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: String,
    pub name: Option<String>,
    pub machine_name: Option<String>,
    pub content: Option<Vec<u8>>,
    pub expiration_date: Option<f64>,
}
impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("serial_number", &self.serial_number)
            .field("machine_name", &self.machine_name)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct AppId {
    pub app_id_id: String,
    pub identifier: String,
    pub name: String,
    pub features: Dictionary,
    pub expiration_date: Option<f64>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct AppIds {
    pub app_ids: Vec<AppId>,
    pub available_quantity: Option<i64>,
    pub max_quantity: Option<u64>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct AppGroup {
    pub application_group: String,
    pub identifier: String,
    pub name: Option<String>,
}
#[derive(Clone, PartialEq)]
pub struct Profile {
    pub app_id_id: String,
    pub encoded_profile: Vec<u8>,
    pub filename: Option<String>,
    pub uuid: Option<String>,
    pub expiration_date: Option<f64>,
}
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profile")
            .field("app_id_id", &self.app_id_id)
            .field("uuid", &self.uuid)
            .finish_non_exhaustive()
    }
}
/// Owns the in-memory GSA authorization and requests fresh anisette per call.
pub struct Developer<T = Https> {
    session: Session,
    transport: T,
    anisette: Box<dyn AnisetteProvider>,
}
impl Developer<Https> {
    pub fn new(session: Session, anisette: Box<dyn AnisetteProvider>) -> Result<Self> {
        Ok(Self::with_transport(session, anisette, Https::new()?))
    }
}
impl<T: Transport> Developer<T> {
    pub fn with_transport(
        session: Session,
        anisette: Box<dyn AnisetteProvider>,
        transport: T,
    ) -> Self {
        Self {
            session,
            transport,
            anisette,
        }
    }
    pub fn from_authenticated(session: Session, gsa: Gsa<T>) -> Self {
        let (transport, anisette) = gsa.into_parts();
        Self::with_transport(session, anisette, transport)
    }
    fn call(&mut self, operation: &str, body: Dictionary) -> Result<Value> {
        let platform = if operation == "listTeams" { "" } else { "ios/" };
        let url = format!("{BASE}{platform}{operation}.action?clientId=XABBG36SBA");
        let mut request = Dictionary::from_iter([
            ("clientId", Value::from("XABBG36SBA")),
            ("protocolVersion", Value::from("QH65B2")),
            ("requestId", Value::from(uuid()?)),
            ("userLocale", Value::Array(vec!["en_US".into()])),
        ]);
        for (k, v) in body {
            if request.contains_key(&k) {
                return Err(Error::new(
                    ErrorCode::InvalidArguments,
                    "reserved Developer Services request field",
                ));
            }
            request.insert(k, v);
        }
        let mut request = Request::post(url, Value::Dictionary(request).to_xml())
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "text/x-xml-plist")
            .header("X-Apple-App-Info", "com.apple.gs.xcode.auth")
            .header("X-Xcode-Version", "15.0 (15A240d)")
            .header("X-Apple-GS-Token", self.session.token())
            .header("X-Apple-I-Identity-Id", &self.session.adsid)
            .max_body(16 * 1024 * 1024);
        request.headers.extend(self.anisette.headers()?.headers);
        let response = self.transport.send(&request).map_err(|_| {
            Error::new(
                ErrorCode::AppleTransportError,
                "Developer Services transport failed",
            )
        })?;
        if !response.is_success() {
            return Err(Error::new(
                ErrorCode::AppleTransportError,
                format!("Developer Services HTTP {}", response.status),
            ));
        }
        if response.body.len() > request.max_body {
            return Err(malformed("response size"));
        }
        let p = plist::from_bytes(&response.body).map_err(|_| malformed("response plist"))?;
        let c = p
            .get("resultCode")
            .and_then(Value::as_i64)
            .ok_or_else(|| malformed("resultCode"))?;
        if c != 0 {
            let message = p
                .get("userString")
                .or_else(|| p.get("resultString"))
                .and_then(Value::as_str)
                .unwrap_or("Apple rejected the operation");
            let lower = message.to_ascii_lowercase();
            let error = if operation == "downloadTeamProvisioningProfile" {
                ErrorCode::ProfileDownloadFailed
            } else if lower.contains("limit") || lower.contains("maximum") {
                match operation {
                    "addDevice" => ErrorCode::DeviceLimitReached,
                    "submitDevelopmentCSR" => ErrorCode::CertificateLimitReached,
                    "addAppId" => ErrorCode::AppIdQuotaExceeded,
                    _ => ErrorCode::AppleApiError,
                }
            } else {
                ErrorCode::AppleApiError
            };
            return Err(Error::new(
                error,
                format!(
                    "Apple result {c}: {}",
                    description(message, &[self.session.token()])
                ),
            ));
        }
        Ok(p)
    }
    fn list<V>(
        &mut self,
        op: &str,
        body: Dictionary,
        key: &str,
        parse: impl Fn(&Value) -> Result<V>,
    ) -> Result<Vec<V>> {
        let p = self.call(op, body)?;
        p.get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| malformed(key))?
            .iter()
            .map(parse)
            .collect()
    }
    pub fn list_teams(&mut self) -> Result<Vec<Team>> {
        self.list("listTeams", Dictionary::new(), "teams", |v| {
            Ok(Team {
                team_id: string(v, "teamId")?,
                name: optional(v, "name"),
                kind: optional(v, "type"),
            })
        })
    }
    pub fn select_team(&mut self, id: Option<&str>) -> Result<Team> {
        let teams = self.list_teams()?;
        teams
            .into_iter()
            .find(|t| id.is_none_or(|id| t.team_id == id))
            .ok_or_else(|| Error::new(ErrorCode::TeamNotFound, "no matching developer team"))
    }
    pub fn list_devices(&mut self, t: &str) -> Result<Vec<Device>> {
        self.list("listDevices", team(t), "devices", parse_device)
    }
    pub fn add_device(&mut self, t: &str, name: &str, udid: &str) -> Result<Device> {
        let mut body = team(t);
        body.insert("name", name);
        body.insert("deviceNumber", udid);
        let p = self.call("addDevice", body)?;
        parse_device(p.get("device").ok_or_else(|| malformed("device"))?)
    }
    pub fn delete_device(&mut self, t: &str, device_id: &str) -> Result<()> {
        self.call("deleteDevice", with_id(t, "deviceId", device_id))?;
        Ok(())
    }
    pub fn list_development_certs(&mut self, t: &str) -> Result<Vec<Certificate>> {
        let certificates = self.list("listAllDevelopmentCerts", team(t), "certificates", |v| {
            Ok(Certificate {
                platform: optional(v, "certificatePlatform").or_else(|| {
                    v.get("certificateType")
                        .and_then(|v| optional(v, "platform"))
                }),
                certificate_id: optional(v, "certificateId"),
                serial_number: string(v, "serialNumber")?,
                name: optional(v, "name"),
                machine_name: optional(v, "machineName"),
                content: v
                    .get("certContent")
                    .and_then(Value::as_data)
                    .map(|b| b.to_vec()),
                expiration_date: date(v, "expirationDate"),
            })
        })?;
        Ok(certificates
            .into_iter()
            .filter(|c| {
                c.platform
                    .as_ref()
                    .is_none_or(|p| p.eq_ignore_ascii_case("ios"))
            })
            .collect())
    }
    /// Returns Apple's certRequestId. Retrieve the issued certificate by listing.
    pub fn submit_development_csr(&mut self, t: &str, csr_pem: &str) -> Result<String> {
        let mut body = team(t);
        body.insert("csrContent", csr_pem);
        body.insert("machineName", "Sideloader");
        body.insert("machineId", uuid()?);
        let p = self.call("submitDevelopmentCSR", body)?;
        string(
            p.get("certRequest")
                .ok_or_else(|| malformed("certRequest"))?,
            "certRequestId",
        )
    }
    pub fn revoke_development_cert(&mut self, t: &str, serial: &str) -> Result<()> {
        self.call("revokeDevelopmentCert", with_id(t, "serialNumber", serial))?;
        Ok(())
    }
    pub fn list_app_ids(&mut self, t: &str) -> Result<AppIds> {
        let p = self.call("listAppIds", team(t))?;
        Ok(AppIds {
            app_ids: p
                .get("appIds")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("appIds"))?
                .iter()
                .map(parse_app)
                .collect::<Result<_>>()?,
            available_quantity: p.get("availableQuantity").and_then(Value::as_i64),
            max_quantity: p.get("maxQuantity").and_then(Value::as_u64),
        })
    }
    pub fn add_app_id(&mut self, t: &str, identifier: &str, name: &str) -> Result<AppId> {
        let mut body = team(t);
        body.insert("identifier", identifier);
        body.insert("name", normalize_app_name(name));
        let p = self.call("addAppId", body)?;
        parse_app(p.get("appId").ok_or_else(|| malformed("appId"))?)
    }
    pub fn update_app_id(&mut self, t: &str, id: &str, features: Dictionary) -> Result<AppId> {
        let mut body = with_id(t, "appIdId", id);
        for (k, v) in features {
            if body.contains_key(&k) {
                return Err(Error::new(
                    ErrorCode::InvalidArguments,
                    "feature overrides App ID or team",
                ));
            }
            body.insert(k, v);
        }
        let p = self.call("updateAppId", body)?;
        parse_app(p.get("appId").ok_or_else(|| malformed("appId"))?)
    }
    pub fn delete_app_id(&mut self, t: &str, id: &str) -> Result<()> {
        self.call("deleteAppId", with_id(t, "appIdId", id))?;
        Ok(())
    }
    pub fn list_app_groups(&mut self, t: &str) -> Result<Vec<AppGroup>> {
        self.list(
            "listApplicationGroups",
            team(t),
            "applicationGroupList",
            parse_group,
        )
    }
    pub fn add_app_group(&mut self, t: &str, identifier: &str, name: &str) -> Result<AppGroup> {
        let mut body = team(t);
        body.insert("identifier", identifier);
        body.insert("name", normalize_app_name(name));
        let p = self.call("addApplicationGroup", body)?;
        parse_group(
            p.get("applicationGroup")
                .ok_or_else(|| malformed("applicationGroup"))?,
        )
    }
    pub fn assign_app_group(&mut self, t: &str, id: &str, group: &str) -> Result<()> {
        let mut body = with_id(t, "appIdId", id);
        body.insert("applicationGroups", group);
        self.call("assignApplicationGroupToAppId", body)?;
        Ok(())
    }
    pub fn download_team_provisioning_profile(&mut self, t: &str, id: &str) -> Result<Profile> {
        let p = self.call("downloadTeamProvisioningProfile", with_id(t, "appIdId", id))?;
        let v = p
            .get("provisioningProfile")
            .ok_or_else(|| malformed("provisioningProfile"))?;
        let profile_id = string(v, "appIdId")?;
        if profile_id != id {
            return Err(Error::new(
                ErrorCode::ProfileDownloadFailed,
                "profile belongs to a different App ID",
            ));
        }
        let bytes = v
            .get("encodedProfile")
            .and_then(Value::as_data)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| malformed("encodedProfile"))?;
        Ok(Profile {
            app_id_id: profile_id,
            encoded_profile: bytes.to_vec(),
            filename: optional(v, "filename"),
            uuid: optional(v, "UUID"),
            expiration_date: date(v, "dateExpire"),
        })
    }
}
fn parse_device(v: &Value) -> Result<Device> {
    Ok(Device {
        device_id: string(v, "deviceId")?,
        udid: string(v, "deviceNumber")?,
        name: optional(v, "name"),
        status: optional(v, "status"),
    })
}
fn parse_app(v: &Value) -> Result<AppId> {
    Ok(AppId {
        app_id_id: string(v, "appIdId")?,
        identifier: string(v, "identifier")?,
        name: string(v, "name")?,
        features: v
            .get("features")
            .and_then(Value::as_dict)
            .cloned()
            .ok_or_else(|| malformed("features"))?,
        expiration_date: date(v, "expirationDate"),
    })
}
fn parse_group(v: &Value) -> Result<AppGroup> {
    Ok(AppGroup {
        application_group: string(v, "applicationGroup")?,
        identifier: string(v, "identifier")?,
        name: optional(v, "name"),
    })
}
/// Apple rejects App ID and App Group names containing non-alphanumeric
/// characters, so keep only ASCII alphanumerics (upstream does the same),
/// falling back to `App` when nothing remains.
pub fn normalize_app_name(name: &str) -> String {
    let kept: String = name.chars().filter(char::is_ascii_alphanumeric).collect();
    if kept.is_empty() {
        "App".to_owned()
    } else {
        kept
    }
}

/// PKCS#10 SHA256/RSA CSR for development certificate submission.
pub fn make_csr(
    key: &crate::crypto::rsa_keygen::RsaPrivateKey,
    common_name: &str,
) -> Result<String> {
    let subject = der::sequence([der::set_of([der::sequence([
        der::oid("2.5.4.3"),
        der::utf8_string(common_name),
    ])])]);
    let info = der::sequence([
        der::integer(0),
        subject,
        key.subject_public_key_info_der(),
        der::tlv(0xa0, &[]),
    ]);
    let signature = key
        .sign_sha256(&info)
        .map_err(|_| Error::new(ErrorCode::AppleApiError, "CSR signing failed"))?;
    let csr = der::sequence([
        info,
        der::sequence([der::oid("1.2.840.113549.1.1.11"), der::null()]),
        der::bit_string(&signature),
    ]);
    Ok(crate::crypto::rsa_keygen::pem_encode(
        "CERTIFICATE REQUEST",
        &csr,
    ))
}
#[cfg(test)]
mod tests;
