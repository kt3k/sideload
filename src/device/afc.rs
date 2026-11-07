//! AFC client (SPEC Section 10.3): upload the signed bundle to the device's
//! media area (`PublicStaging`).
//!
//! Packet layout, all little-endian: a 40-byte header
//! (`magic`, `entire_len`, `header_payload_len`, `packet_num`, `operation`),
//! then the header payload, then the data payload. `header_payload_len`
//! counts the header; `entire_len` counts the whole packet.
//!
//! Reference: idevice (MIT), libimobiledevice AFC.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::{Error, ErrorCode, Result};

pub const MAGIC: u64 = 0x4141_504c_3641_4643; // "CFA6LPAA" little-endian
const HEADER_LEN: u64 = 40;
const MAX_PACKET: u64 = 1 << 30;
/// AFC caps a single write; chunk larger files.
const WRITE_CHUNK: usize = 64 * 1024;

// Opcodes (SPEC 10.3 needs only a few).
const OP_STATUS: u64 = 0x01;
const OP_REMOVE_PATH: u64 = 0x08;
const OP_MAKE_DIR: u64 = 0x09;
const OP_GET_FILE_INFO: u64 = 0x0a;
const OP_FILE_OPEN: u64 = 0x0d;
const OP_FILE_WRITE: u64 = 0x10;
const OP_FILE_CLOSE: u64 = 0x14;
const OP_REMOVE_PATH_AND_CONTENTS: u64 = 0x22;

/// `w`: create/truncate for writing.
const FOPEN_WRONLY: u64 = 0x03;

fn transport_err(msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::DeviceTransportError, format!("AFC: {msg}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub operation: u64,
    pub header_payload: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Encodes a packet with `packet_num`.
pub fn encode(packet: &Packet, packet_num: u64) -> Vec<u8> {
    let header_payload_len = HEADER_LEN + packet.header_payload.len() as u64;
    let entire_len = header_payload_len + packet.payload.len() as u64;
    let mut out = Vec::with_capacity(entire_len as usize);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&entire_len.to_le_bytes());
    out.extend_from_slice(&header_payload_len.to_le_bytes());
    out.extend_from_slice(&packet_num.to_le_bytes());
    out.extend_from_slice(&packet.operation.to_le_bytes());
    out.extend_from_slice(&packet.header_payload);
    out.extend_from_slice(&packet.payload);
    out
}

fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

/// Reads one packet.
pub fn read_packet(r: &mut impl Read) -> Result<Packet> {
    let mut header = [0u8; HEADER_LEN as usize];
    r.read_exact(&mut header).map_err(transport_err)?;
    if u64_le(&header[0..8]) != MAGIC {
        return Err(transport_err("bad packet magic"));
    }
    let entire_len = u64_le(&header[8..16]);
    let header_payload_len = u64_le(&header[16..24]);
    let operation = u64_le(&header[32..40]);
    if header_payload_len < HEADER_LEN || entire_len < header_payload_len || entire_len > MAX_PACKET
    {
        return Err(transport_err("inconsistent packet lengths"));
    }
    let mut header_payload = vec![0u8; (header_payload_len - HEADER_LEN) as usize];
    r.read_exact(&mut header_payload).map_err(transport_err)?;
    let mut payload = vec![0u8; (entire_len - header_payload_len) as usize];
    r.read_exact(&mut payload).map_err(transport_err)?;
    Ok(Packet {
        operation,
        header_payload,
        payload,
    })
}

/// Maps an AFC status code to a message (0 is success).
fn status_message(code: u64) -> &'static str {
    match code {
        0 => "success",
        1 => "unknown error",
        2 => "operation header invalid",
        3 => "no resources",
        4 => "read error",
        5 => "write error",
        6 => "unknown packet type",
        7 => "invalid argument",
        8 => "object not found",
        9 => "object is directory",
        10 => "permission denied",
        13 => "object exists",
        14 => "object busy",
        15 => "no space left",
        _ => "AFC error",
    }
}

pub struct AfcClient<S> {
    stream: S,
    packet_num: u64,
}

impl<S: Read + Write> AfcClient<S> {
    pub fn new(stream: S) -> AfcClient<S> {
        AfcClient {
            stream,
            packet_num: 0,
        }
    }

    fn send(&mut self, packet: Packet) -> Result<Packet> {
        let encoded = encode(&packet, self.packet_num);
        self.packet_num += 1;
        self.stream.write_all(&encoded).map_err(transport_err)?;
        self.stream.flush().map_err(transport_err)?;
        let reply = read_packet(&mut self.stream)?;
        if reply.operation == OP_STATUS {
            let code = reply.header_payload.get(..8).map(u64_le).unwrap_or(1);
            if code != 0 {
                return Err(transport_err(format!(
                    "{} (code {code})",
                    status_message(code)
                )));
            }
        }
        Ok(reply)
    }

    fn op(&mut self, operation: u64, header_payload: Vec<u8>, payload: Vec<u8>) -> Result<Packet> {
        self.send(Packet {
            operation,
            header_payload,
            payload,
        })
    }

    pub fn make_directory(&mut self, path: &str) -> Result<()> {
        self.op(OP_MAKE_DIR, path.as_bytes().to_vec(), Vec::new())?;
        Ok(())
    }

    pub fn remove_path_and_contents(&mut self, path: &str) -> Result<()> {
        self.op(
            OP_REMOVE_PATH_AND_CONTENTS,
            path.as_bytes().to_vec(),
            Vec::new(),
        )?;
        Ok(())
    }

    pub fn remove_path(&mut self, path: &str) -> Result<()> {
        self.op(OP_REMOVE_PATH, path.as_bytes().to_vec(), Vec::new())?;
        Ok(())
    }

    /// `GetFileInfo`: the attribute key/value map, or `None` if the path does
    /// not exist.
    pub fn file_info(&mut self, path: &str) -> Result<Option<BTreeMap<String, String>>> {
        match self.op(OP_GET_FILE_INFO, path.as_bytes().to_vec(), Vec::new()) {
            Ok(reply) => Ok(Some(parse_kv(&reply.payload))),
            Err(e) if e.message.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn exists(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_info(path)?.is_some())
    }

    /// Writes `data` to `path`, creating/truncating it, in bounded chunks.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let mut header_payload = FOPEN_WRONLY.to_le_bytes().to_vec();
        header_payload.extend_from_slice(path.as_bytes());
        let reply = self.op(OP_FILE_OPEN, header_payload, Vec::new())?;
        let fd = reply
            .header_payload
            .get(..8)
            .map(u64_le)
            .ok_or_else(|| transport_err("FileOpen reply has no handle"))?;

        // Write in bounded chunks; an empty file is just open + close.
        let result = data.chunks(WRITE_CHUNK).try_for_each(|chunk| {
            self.op(OP_FILE_WRITE, fd.to_le_bytes().to_vec(), chunk.to_vec())
                .map(|_| ())
        });
        // Always close, even on write failure.
        let close = self.op(OP_FILE_CLOSE, fd.to_le_bytes().to_vec(), Vec::new());
        result.and(close.map(|_| ()))
    }
}

/// Parses NUL-separated key/value attribute strings.
fn parse_kv(payload: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut parts = payload
        .split(|&b| b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok());
    while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
        map.insert(k.to_owned(), v.to_owned());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A fake device: queued replies to hand back, and everything written.
    struct MockDevice {
        replies: std::collections::VecDeque<Vec<u8>>,
        written: Vec<u8>,
        read_buf: Cursor<Vec<u8>>,
    }

    impl MockDevice {
        fn new(replies: Vec<Packet>) -> MockDevice {
            MockDevice {
                replies: replies.iter().map(|p| encode(p, 0)).collect(),
                written: Vec::new(),
                read_buf: Cursor::new(Vec::new()),
            }
        }
    }

    impl Read for MockDevice {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.read_buf.position() as usize >= self.read_buf.get_ref().len() {
                if let Some(next) = self.replies.pop_front() {
                    self.read_buf = Cursor::new(next);
                }
            }
            self.read_buf.read(buf)
        }
    }

    impl Write for MockDevice {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn status(code: u64) -> Packet {
        Packet {
            operation: OP_STATUS,
            header_payload: code.to_le_bytes().to_vec(),
            payload: Vec::new(),
        }
    }

    #[test]
    fn packet_roundtrip() {
        let p = Packet {
            operation: OP_FILE_WRITE,
            header_payload: 7u64.to_le_bytes().to_vec(),
            payload: b"hello".to_vec(),
        };
        let bytes = encode(&p, 3);
        assert_eq!(u64_le(&bytes[24..32]), 3); // packet_num
        assert_eq!(read_packet(&mut Cursor::new(bytes)).unwrap(), p);
    }

    #[test]
    fn read_packet_rejects_bad_magic_and_lengths() {
        let mut bad = vec![0u8; 40];
        assert!(read_packet(&mut Cursor::new(bad.clone())).is_err());
        bad[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        bad[8..16].copy_from_slice(&8u64.to_le_bytes()); // entire_len < header
        assert!(read_packet(&mut Cursor::new(bad)).is_err());
    }

    #[test]
    fn make_directory_and_status_error() {
        let mut client = AfcClient::new(MockDevice::new(vec![status(0)]));
        assert!(client.make_directory("PublicStaging").is_ok());

        let mut client = AfcClient::new(MockDevice::new(vec![status(10)]));
        let err = client.make_directory("/x").unwrap_err();
        assert_eq!(err.code, ErrorCode::DeviceTransportError);
        assert!(err.message.contains("permission denied"));
    }

    #[test]
    fn file_info_present_and_absent() {
        let info = Packet {
            operation: 0x02, // Data
            header_payload: Vec::new(),
            payload: b"st_size\x000\x00st_ifmt\x00S_IFDIR\x00".to_vec(),
        };
        let mut client = AfcClient::new(MockDevice::new(vec![info]));
        let map = client.file_info("PublicStaging").unwrap().unwrap();
        assert_eq!(map.get("st_ifmt").map(String::as_str), Some("S_IFDIR"));

        let mut client = AfcClient::new(MockDevice::new(vec![status(8)])); // not found
        assert_eq!(client.file_info("/missing").unwrap(), None);
        assert!(
            !AfcClient::new(MockDevice::new(vec![status(8)]))
                .exists("/x")
                .unwrap()
        );
    }

    #[test]
    fn write_file_opens_writes_and_closes() {
        // FileOpen -> fd 9; Write -> status 0; Close -> status 0.
        let open = Packet {
            operation: 0x0e, // FileOpenRes
            header_payload: 9u64.to_le_bytes().to_vec(),
            payload: Vec::new(),
        };
        let mut client = AfcClient::new(MockDevice::new(vec![open, status(0), status(0)]));
        assert!(
            client
                .write_file("PublicStaging/App.app/bin", b"data")
                .is_ok()
        );
        // Three packets written: open, write, close.
        let mut cursor = Cursor::new(client.stream.written.clone());
        let p1 = read_packet(&mut cursor).unwrap();
        assert_eq!(p1.operation, OP_FILE_OPEN);
        assert_eq!(u64_le(&p1.header_payload[..8]), FOPEN_WRONLY);
        let p2 = read_packet(&mut cursor).unwrap();
        assert_eq!(p2.operation, OP_FILE_WRITE);
        assert_eq!(p2.payload, b"data");
        assert_eq!(read_packet(&mut cursor).unwrap().operation, OP_FILE_CLOSE);
    }

    #[test]
    fn write_empty_file_still_opens_and_closes() {
        let open = Packet {
            operation: 0x0e,
            header_payload: 1u64.to_le_bytes().to_vec(),
            payload: Vec::new(),
        };
        let mut client = AfcClient::new(MockDevice::new(vec![open, status(0)]));
        assert!(client.write_file("PublicStaging/empty", b"").is_ok());
        let mut cursor = Cursor::new(client.stream.written.clone());
        assert_eq!(read_packet(&mut cursor).unwrap().operation, OP_FILE_OPEN);
        assert_eq!(read_packet(&mut cursor).unwrap().operation, OP_FILE_CLOSE);
    }
}
