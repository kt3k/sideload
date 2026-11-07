//! usbmuxd client (SPEC Section 10.1): list connected devices, read pair
//! records, and open a connection to a device port (for lockdownd).
//!
//! Wire format of one packet: `size`, `version`, `message`, `tag` (each a
//! little-endian u32), then an XML plist body. `size` counts the 16-byte
//! header plus the body. We use the plist protocol (version 1, message 8).
//!
//! Reference: idevice (MIT), libusbmuxd.

use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::formats::plist::{self, Dictionary, Value};
use crate::{Error, ErrorCode, Result};

const PLIST_VERSION: u32 = 1;
const PLIST_MESSAGE: u32 = 8;
const USBMUX_VERSION: i64 = 3;
const MAX_PACKET: u32 = 1 << 24;

#[cfg(unix)]
pub const SOCKET_FILE: &str = "/var/run/usbmuxd";
pub const TCP_PORT: u16 = 27015;

fn transport_err(msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::DeviceTransportError, format!("usbmuxd: {msg}"))
}

/// A device as reported by usbmuxd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbmuxdDevice {
    pub device_id: u32,
    /// The device's serial number, i.e. its UDID.
    pub udid: String,
    /// `USB` or `Network`.
    pub connection_type: String,
}

// ---------------------------------------------------------------- packet codec

/// Encodes a request packet (header + XML plist body).
pub fn encode_packet(tag: u32, body: &Dictionary) -> Vec<u8> {
    let xml = Value::Dictionary(body.clone()).to_xml();
    let size = (xml.len() + 16) as u32;
    let mut out = Vec::with_capacity(xml.len() + 16);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&PLIST_VERSION.to_le_bytes());
    out.extend_from_slice(&PLIST_MESSAGE.to_le_bytes());
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&xml);
    out
}

/// Reads one reply packet from `r` and returns its plist body.
pub fn read_packet(r: &mut impl Read) -> Result<Dictionary> {
    let mut header = [0u8; 16];
    r.read_exact(&mut header).map_err(transport_err)?;
    let size = u32::from_le_bytes(header[0..4].try_into().unwrap());
    if !(16..=MAX_PACKET).contains(&size) {
        return Err(transport_err(format!("reply size {size} out of range")));
    }
    let mut body = vec![0u8; (size - 16) as usize];
    r.read_exact(&mut body).map_err(transport_err)?;
    match plist::from_bytes(&body) {
        Ok(Value::Dictionary(d)) => Ok(d),
        _ => Err(transport_err("reply is not a plist dictionary")),
    }
}

// ---------------------------------------------------------------- connection

/// A socket to usbmuxd. After a successful `connect_to_device`, the same
/// socket carries the device service, so the stream is handed out.
pub enum Socket {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Socket::Unix(s) => s.read(buf),
            Socket::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Socket::Unix(s) => s.write(buf),
            Socket::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Socket::Unix(s) => s.flush(),
            Socket::Tcp(s) => s.flush(),
        }
    }
}

/// Connects to the usbmuxd socket. Honors `USBMUXD_SOCKET_ADDRESS`
/// (`UNIX:/path` or `host:port`); otherwise the Unix socket on Unix and TCP
/// `127.0.0.1:27015` on Windows.
pub fn connect_socket() -> Result<Socket> {
    if let Some(addr) = std::env::var_os("USBMUXD_SOCKET_ADDRESS").filter(|v| !v.is_empty()) {
        let addr = addr.to_string_lossy().into_owned();
        #[cfg(unix)]
        if let Some(path) = addr.strip_prefix("UNIX:") {
            return Ok(Socket::Unix(
                UnixStream::connect(path).map_err(transport_err)?,
            ));
        }
        return Ok(Socket::Tcp(
            TcpStream::connect(&addr).map_err(transport_err)?,
        ));
    }
    #[cfg(unix)]
    {
        Ok(Socket::Unix(UnixStream::connect(SOCKET_FILE).map_err(
            |e| {
                transport_err(format!(
                    "cannot connect to {SOCKET_FILE} ({e}); is usbmuxd running?"
                ))
            },
        )?))
    }
    #[cfg(not(unix))]
    {
        Ok(Socket::Tcp(
            TcpStream::connect(("127.0.0.1", TCP_PORT)).map_err(|e| {
                transport_err(format!("cannot connect to 127.0.0.1:{TCP_PORT} ({e}); is Apple Mobile Device Support installed?"))
            })?,
        ))
    }
}

/// A usbmuxd session over one socket, assigning request tags.
pub struct Usbmuxd {
    socket: Socket,
    tag: u32,
}

impl Usbmuxd {
    pub fn connect() -> Result<Usbmuxd> {
        Ok(Usbmuxd::with_socket(connect_socket()?))
    }

    pub fn with_socket(socket: Socket) -> Usbmuxd {
        Usbmuxd { socket, tag: 0 }
    }

    fn request(&mut self, body: &Dictionary) -> Result<Dictionary> {
        self.tag += 1;
        self.socket
            .write_all(&encode_packet(self.tag, body))
            .map_err(transport_err)?;
        self.socket.flush().map_err(transport_err)?;
        read_packet(&mut self.socket)
    }

    /// `ListDevices`.
    pub fn list_devices(&mut self) -> Result<Vec<UsbmuxdDevice>> {
        let reply = self.request(&dict([
            ("MessageType", Value::from("ListDevices")),
            ("kLibUSBMuxVersion", Value::Integer(USBMUX_VERSION.into())),
        ]))?;
        parse_device_list(&reply)
    }

    /// `ReadBUID` (the host identifier lockdownd pairing needs).
    pub fn read_buid(&mut self) -> Result<String> {
        let reply = self.request(&dict([("MessageType", Value::from("ReadBUID"))]))?;
        reply
            .get("BUID")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| transport_err("ReadBUID reply has no BUID"))
    }

    /// `ReadPairRecord`: the stored pairing plist for `udid`, or `None` when
    /// the device is not paired.
    pub fn read_pair_record(&mut self, udid: &str) -> Result<Option<Vec<u8>>> {
        let reply = self.request(&dict([
            ("MessageType", Value::from("ReadPairRecord")),
            ("PairRecordID", Value::from(udid)),
        ]))?;
        match reply.get("PairRecordData") {
            Some(Value::Data(d)) => Ok(Some(d.clone())),
            _ => Ok(None),
        }
    }

    /// `Connect`: opens `port` on the device. On success the underlying
    /// socket now speaks to that device service, so it is returned.
    /// `port` is given in host byte order and sent big-endian, as usbmuxd
    /// expects.
    pub fn connect_to_device(mut self, device_id: u32, port: u16) -> Result<Socket> {
        let reply = self.request(&dict([
            ("MessageType", Value::from("Connect")),
            ("DeviceID", Value::Integer(i64::from(device_id).into())),
            ("PortNumber", Value::Integer(i64::from(port.to_be()).into())),
        ]))?;
        match connect_result(&reply)? {
            0 => Ok(self.socket),
            1 => Err(transport_err("Connect failed: bad command")),
            2 => Err(transport_err("Connect failed: unknown device")),
            3 => Err(Error::new(
                ErrorCode::DeviceTransportError,
                "Connect refused by the device (is a service already using the port?)",
            )),
            n => Err(transport_err(format!("Connect failed with code {n}"))),
        }
    }
}

fn dict<const N: usize>(entries: [(&str, Value); N]) -> Dictionary {
    entries.into_iter().collect()
}

/// `Number` result code of a `Connect`/`Result` reply.
pub fn connect_result(reply: &Dictionary) -> Result<u64> {
    reply
        .get("Number")
        .and_then(Value::as_u64)
        .ok_or_else(|| transport_err("reply has no Number field"))
}

/// Parses a `ListDevices` reply.
pub fn parse_device_list(reply: &Dictionary) -> Result<Vec<UsbmuxdDevice>> {
    let list = reply
        .get("DeviceList")
        .and_then(Value::as_array)
        .ok_or_else(|| transport_err("ListDevices reply has no DeviceList"))?;
    let mut devices = Vec::new();
    for entry in list {
        let device_id = entry
            .get("DeviceID")
            .and_then(Value::as_u64)
            .ok_or_else(|| transport_err("device entry has no DeviceID"))?;
        let props = entry
            .get("Properties")
            .and_then(Value::as_dict)
            .ok_or_else(|| transport_err("device entry has no Properties"))?;
        let udid = props
            .get("SerialNumber")
            .and_then(Value::as_str)
            .ok_or_else(|| transport_err("device entry has no SerialNumber"))?;
        devices.push(UsbmuxdDevice {
            device_id: device_id as u32,
            udid: udid.to_owned(),
            connection_type: props
                .get("ConnectionType")
                .and_then(Value::as_str)
                .unwrap_or("USB")
                .to_owned(),
        });
    }
    Ok(devices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A reply packet as usbmuxd would frame it.
    fn reply(body: Dictionary) -> Vec<u8> {
        encode_packet(1, &body)
    }

    #[test]
    fn packet_roundtrip() {
        let body = dict([("MessageType", Value::from("ListDevices"))]);
        let bytes = encode_packet(5, &body);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            bytes.len() as u32
        );
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            PLIST_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            PLIST_MESSAGE
        );
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 5);
        let mut cursor = Cursor::new(&bytes[..]);
        assert_eq!(read_packet(&mut cursor).unwrap(), body);
    }

    #[test]
    fn read_packet_rejects_bad_size() {
        let mut small = Cursor::new(vec![0u8; 16]); // size 0
        assert_eq!(
            read_packet(&mut small).unwrap_err().code,
            ErrorCode::DeviceTransportError
        );
        let mut huge = Vec::new();
        huge.extend_from_slice(&(MAX_PACKET + 1).to_le_bytes());
        huge.extend_from_slice(&[0u8; 12]);
        assert!(read_packet(&mut Cursor::new(huge)).is_err());
        assert!(read_packet(&mut Cursor::new(vec![0u8; 4])).is_err());
    }

    #[test]
    fn parses_device_list() {
        let props_usb: Dictionary = [
            ("ConnectionType", Value::from("USB")),
            ("SerialNumber", Value::from("00008030-001A2B3C")),
        ]
        .into_iter()
        .collect();
        let dev: Dictionary = [
            ("DeviceID", Value::Integer(42.into())),
            ("Properties", Value::Dictionary(props_usb)),
        ]
        .into_iter()
        .collect();
        let body = dict([("DeviceList", Value::Array(vec![Value::Dictionary(dev)]))]);
        let devices = parse_device_list(&body).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, 42);
        assert_eq!(devices[0].udid, "00008030-001A2B3C");
        assert_eq!(devices[0].connection_type, "USB");

        // Empty list and missing fields.
        assert!(
            parse_device_list(&dict([("DeviceList", Value::Array(vec![]))]))
                .unwrap()
                .is_empty()
        );
        assert!(parse_device_list(&dict([("x", Value::from("y"))])).is_err());
    }

    #[test]
    fn session_over_mock_socket() {
        // A socket preloaded with a ListDevices reply, then a Connect reply.
        let mut script = reply(dict([("DeviceList", Value::Array(vec![]))]));
        script.extend(reply(dict([("Number", Value::Integer(0.into()))])));
        let sock = Socket::Tcp(loopback_with(&script));
        let mut mux = Usbmuxd::with_socket(sock);
        assert!(mux.list_devices().unwrap().is_empty());
        // connect_to_device consumes the session and returns the socket.
        let _device_socket = mux.connect_to_device(1, 62078).unwrap();
    }

    #[test]
    fn connect_error_codes() {
        for (code, expect_refused) in [(1u64, false), (2, false), (3, true)] {
            let sock = Socket::Tcp(loopback_with(&reply(dict([(
                "Number",
                Value::Integer((code as i64).into()),
            )]))));
            let mux = Usbmuxd::with_socket(sock);
            let err = match mux.connect_to_device(1, 62078) {
                Ok(_) => panic!("expected an error for code {code}"),
                Err(e) => e,
            };
            assert_eq!(err.code, ErrorCode::DeviceTransportError);
            assert_eq!(err.message.contains("refused"), expect_refused);
        }
    }

    /// A connected TCP socket preloaded with `data` to read back.
    fn loopback_with(data: &[u8]) -> TcpStream {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let data = data.to_vec();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // Drain the request(s) the client writes, then send the script.
            s.set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.write_all(&data);
            let _ = s.read(&mut buf);
        });
        let client = TcpStream::connect(addr).unwrap();
        let _ = server;
        client
    }
}
