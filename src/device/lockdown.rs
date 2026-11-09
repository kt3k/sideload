//! lockdownd client (SPEC Section 10): start a TLS session with a paired
//! device and ask it to start services (AFC, installation_proxy, misagent).
//!
//! Messages are an XML plist with a 4-byte big-endian length prefix. After
//! `StartSession` the connection is upgraded to TLS using the pairing
//! record's host certificate/key; the device certificate is not verified
//! (as libimobiledevice and isideload do), because it is a self-signed
//! pairing certificate, not part of any public PKI.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use super::pairing::PairingRecord;
use super::usbmuxd::Socket;
use crate::formats::plist::{self, Dictionary, Value};
use crate::{Error, ErrorCode, Result};

pub const LOCKDOWND_PORT: u16 = 62078;
const LABEL: &str = "sideload";
const MAX_MESSAGE: u32 = 1 << 24;

fn transport_err(msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::DeviceTransportError, format!("lockdownd: {msg}"))
}

// ---------------------------------------------------------------- stream

/// A device connection, plain or TLS. The TLS variant boxes the large
/// rustls state.
pub enum DeviceStream {
    Plain(Socket),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, Socket>>),
}

impl Read for DeviceStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DeviceStream::Plain(s) => s.read(buf),
            DeviceStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for DeviceStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            DeviceStream::Plain(s) => s.write(buf),
            DeviceStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            DeviceStream::Plain(s) => s.flush(),
            DeviceStream::Tls(s) => s.flush(),
        }
    }
}

// ---------------------------------------------------------------- plist framing

/// Writes a plist message with its 4-byte big-endian length prefix.
pub fn write_message(w: &mut impl Write, body: &Dictionary) -> Result<()> {
    let xml = Value::Dictionary(body.clone()).to_xml();
    let len = u32::try_from(xml.len()).map_err(|_| transport_err("message too large"))?;
    w.write_all(&len.to_be_bytes()).map_err(transport_err)?;
    w.write_all(&xml).map_err(transport_err)?;
    w.flush().map_err(transport_err)?;
    Ok(())
}

/// Reads one length-prefixed plist message, without interpreting its fields.
/// Used directly by services (installation_proxy, misagent) that give their
/// own meaning to `Error`.
pub fn read_message_raw(r: &mut impl Read) -> Result<Dictionary> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes).map_err(transport_err)?;
    let len = u32::from_be_bytes(len_bytes);
    if len == 0 || len > MAX_MESSAGE {
        return Err(transport_err(format!("message length {len} out of range")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).map_err(transport_err)?;
    match plist::from_bytes(&body) {
        Ok(Value::Dictionary(d)) => Ok(d),
        _ => Err(transport_err("reply is not a plist dictionary")),
    }
}

/// Like `read_message_raw`, but a top-level `Error` string fails the call
/// (lockdownd's own convention).
pub fn read_message(r: &mut impl Read) -> Result<Dictionary> {
    let d = read_message_raw(r)?;
    if let Some(err) = d.get("Error").and_then(Value::as_str) {
        return Err(lockdown_error(err));
    }
    Ok(d)
}

/// lockdownd errors meaning the device is locked or does not trust this
/// computer (SPEC Section 10.1).
const NOT_PAIRED_ERRORS: &[&str] = &[
    "InvalidHostID",
    "InvalidPairRecord",
    "PasswordProtected",
    "PairingDialogResponsePending",
    "UserDeniedPairing",
];

fn lockdown_error(err: &str) -> Error {
    if NOT_PAIRED_ERRORS.contains(&err) {
        Error::new(
            ErrorCode::DeviceNotPaired,
            format!(
                "device returned `{err}`: unlock the device and tap \"Trust This Computer\", \
                 then try again"
            ),
        )
    } else {
        transport_err(format!("device returned error `{err}`"))
    }
}

fn request<const N: usize>(entries: [(&str, Value); N]) -> Dictionary {
    let mut d = Dictionary::new();
    d.insert("Label", LABEL);
    for (k, v) in entries {
        d.insert(k, v);
    }
    d
}

// ---------------------------------------------------------------- TLS

#[derive(Debug)]
struct AcceptDeviceCert {
    schemes: Vec<rustls::SignatureScheme>,
}

impl ServerCertVerifier for AcceptDeviceCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// Builds the mutual-TLS client config for a device session: the host
/// certificate/key as the client identity, and a verifier that accepts the
/// device's self-signed certificate.
pub fn tls_config(pairing: &PairingRecord) -> Result<Arc<rustls::ClientConfig>> {
    let provider = rustls::crypto::ring::default_provider();
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let cert = CertificateDer::from(pairing.host_certificate.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pairing.host_private_key_pkcs8_der(),
    ));
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| transport_err(format!("TLS setup failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptDeviceCert { schemes }))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| transport_err(format!("invalid host certificate or key: {e}")))?;
    Ok(Arc::new(config))
}

/// Wraps a freshly connected service socket in TLS with the pairing config.
pub fn wrap_tls(socket: Socket, config: Arc<rustls::ClientConfig>) -> Result<DeviceStream> {
    let name = ServerName::try_from("Device").expect("static name");
    let conn = rustls::ClientConnection::new(config, name)
        .map_err(|e| transport_err(format!("TLS setup failed: {e}")))?;
    Ok(DeviceStream::Tls(Box::new(rustls::StreamOwned::new(
        conn, socket,
    ))))
}

// ---------------------------------------------------------------- client

pub struct LockdownClient {
    // Always Some except briefly during the TLS upgrade.
    stream: Option<DeviceStream>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub port: u16,
    pub ssl: bool,
}

impl LockdownClient {
    /// Wraps a socket already connected to the device's lockdownd port.
    pub fn new(socket: Socket) -> LockdownClient {
        LockdownClient {
            stream: Some(DeviceStream::Plain(socket)),
            tls_config: None,
        }
    }

    fn transact(&mut self, body: &Dictionary) -> Result<Dictionary> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| transport_err("connection is being upgraded"))?;
        write_message(stream, body)?;
        read_message(stream)
    }

    /// `QueryType` — confirms this is lockdownd.
    pub fn query_type(&mut self) -> Result<String> {
        let reply = self.transact(&request([("Request", Value::from("QueryType"))]))?;
        reply
            .get("Type")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| transport_err("QueryType reply has no Type"))
    }

    /// `GetValue` for a domain-less key, e.g. `DeviceName` or `ProductVersion`.
    pub fn get_value(&mut self, key: &str) -> Result<Value> {
        let reply = self.transact(&request([
            ("Request", Value::from("GetValue")),
            ("Key", Value::from(key)),
        ]))?;
        reply
            .get("Value")
            .cloned()
            .ok_or_else(|| transport_err(format!("GetValue({key}) reply has no Value")))
    }

    /// `SetValue` in `domain` (requires a session).
    pub fn set_value(&mut self, domain: &str, key: &str, value: Value) -> Result<()> {
        self.transact(&request([
            ("Request", Value::from("SetValue")),
            ("Domain", Value::from(domain)),
            ("Key", Value::from(key)),
            ("Value", value),
        ]))?;
        Ok(())
    }

    pub fn device_name(&mut self) -> Result<String> {
        match self.get_value("DeviceName")? {
            Value::String(s) => Ok(s),
            _ => Err(transport_err("DeviceName is not a string")),
        }
    }

    /// `StartSession`, then the TLS upgrade (SPEC Section 10.3). After this,
    /// requests and `StartService` run over TLS.
    pub fn start_session(&mut self, pairing: &PairingRecord) -> Result<()> {
        let reply = self.transact(&request([
            ("Request", Value::from("StartSession")),
            ("HostID", Value::from(pairing.host_id.clone())),
            ("SystemBUID", Value::from(pairing.system_buid.clone())),
        ]))?;
        if reply.get("EnableSessionSSL").and_then(Value::as_bool) != Some(true) {
            return Err(transport_err("device did not enable session SSL"));
        }
        let config = tls_config(pairing)?;
        self.tls_config = Some(config.clone());
        let socket = match self.stream.take() {
            Some(DeviceStream::Plain(s)) => s,
            Some(DeviceStream::Tls(_)) => return Err(transport_err("session already started")),
            None => return Err(transport_err("connection is being upgraded")),
        };
        self.stream = Some(wrap_tls(socket, config)?);
        Ok(())
    }

    /// `StartService`: returns the service's port and whether it needs TLS.
    pub fn start_service(
        &mut self,
        identifier: &str,
        escrow_bag: Option<&[u8]>,
    ) -> Result<Service> {
        let mut req = request([
            ("Request", Value::from("StartService")),
            ("Service", Value::from(identifier)),
        ]);
        if let Some(bag) = escrow_bag {
            req.insert("EscrowBag", Value::Data(bag.to_vec()));
        }
        let reply = self.transact(&req)?;
        let port = reply
            .get("Port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .ok_or_else(|| transport_err(format!("StartService({identifier}) returned no port")))?;
        let ssl = reply.get("EnableServiceSSL").and_then(Value::as_bool) == Some(true);
        Ok(Service { port, ssl })
    }

    /// The TLS config to reuse on service sockets, set after `start_session`.
    pub fn service_tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        self.tls_config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::pairing::tests::sample_record;
    use std::io::Cursor;

    #[test]
    fn message_framing_roundtrip() {
        let body = request([("Request", Value::from("QueryType"))]);
        let mut buf = Vec::new();
        write_message(&mut buf, &body).unwrap();
        assert_eq!(
            u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize,
            buf.len() - 4
        );
        assert_eq!(read_message(&mut Cursor::new(buf)).unwrap(), body);
    }

    #[test]
    fn read_message_surfaces_device_error_and_bad_length() {
        let mut err = Dictionary::new();
        err.insert("Error", "InvalidService");
        let mut buf = Vec::new();
        write_message(&mut buf, &err).unwrap();
        assert!(
            read_message(&mut Cursor::new(buf))
                .unwrap_err()
                .message
                .contains("InvalidService")
        );

        let mut zero = Cursor::new(vec![0u8; 4]);
        assert!(read_message(&mut zero).is_err());
        let mut huge = (MAX_MESSAGE + 1).to_be_bytes().to_vec();
        huge.extend_from_slice(&[0u8; 4]);
        assert!(read_message(&mut Cursor::new(huge)).is_err());
    }

    /// Replies scripted onto a plain in-memory stream, exercising the
    /// request/response logic without TLS (no StartSession here).
    #[test]
    fn query_type_and_start_service_parsing() {
        fn framed(d: Dictionary) -> Vec<u8> {
            let mut b = Vec::new();
            write_message(&mut b, &d).unwrap();
            b
        }
        let mut qt = Dictionary::new();
        qt.insert("Type", "com.apple.mobile.lockdown");
        let mut svc = Dictionary::new();
        svc.insert("Port", Value::Integer(44000.into()));
        svc.insert("EnableServiceSSL", Value::Boolean(true));
        let mut script = framed(qt);
        script.extend(framed(svc));

        // Drive write_message/read_message directly over the scripted buffer.
        let mut stream = Cursor::new(script);
        assert_eq!(
            read_message(&mut stream)
                .unwrap()
                .get("Type")
                .unwrap()
                .as_str(),
            Some("com.apple.mobile.lockdown")
        );
        let service = read_message(&mut stream).unwrap();
        assert_eq!(service.get("Port").unwrap().as_u64(), Some(44000));
        assert_eq!(
            service.get("EnableServiceSSL").unwrap().as_bool(),
            Some(true)
        );
    }

    #[test]
    fn tls_config_builds_from_pairing_record() {
        let (bytes, _) = sample_record();
        let record = PairingRecord::parse(&bytes).unwrap();
        // The host identity (self-signed test cert + its key) is accepted by
        // rustls; building the config must not error.
        assert!(tls_config(&record).is_ok());
    }

    #[test]
    fn pairing_errors_map_to_device_not_paired() {
        assert_eq!(
            lockdown_error("PasswordProtected").code,
            ErrorCode::DeviceNotPaired
        );
        assert_eq!(
            lockdown_error("InvalidHostID").code,
            ErrorCode::DeviceNotPaired
        );
        assert_eq!(
            lockdown_error("SomethingElse").code,
            ErrorCode::DeviceTransportError
        );
    }
}
