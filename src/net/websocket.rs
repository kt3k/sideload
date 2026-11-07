//! Minimal RFC 6455 WebSocket client (text messages only), used by the
//! anisette-v3 provisioning session.

use std::io::{BufReader, Read, Write};

use super::http::{Client, Stream, Url, read_head};
use super::{NetError, NetResult};
use crate::crypto;
use crate::formats::base64;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Close,
}

pub struct WebSocket {
    io: BufReader<Stream>,
}

fn err(msg: impl Into<String>) -> NetError {
    NetError::transport(format!("WebSocket: {}", msg.into()))
}

/// The `Sec-WebSocket-Accept` value for `key`.
pub fn accept_key(key: &str) -> String {
    base64::encode(&crypto::sha1(format!("{key}{GUID}").as_bytes()))
}

impl WebSocket {
    /// Connects to a `ws://` or `wss://` URL.
    pub fn connect(client: &Client, url: &str) -> NetResult<WebSocket> {
        let http_url = if let Some(rest) = url.strip_prefix("wss://") {
            format!("https://{rest}")
        } else if let Some(rest) = url.strip_prefix("ws://") {
            format!("http://{rest}")
        } else {
            return Err(err(format!("not a ws:// or wss:// URL: {url}")));
        };
        let u = Url::parse(&http_url)?;
        let mut stream = client.open(&u)?;
        let key = base64::encode(&crypto::random_bytes(16).map_err(|e| err(e.to_string()))?);
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: {}\r\n\r\n",
            u.path,
            u.authority(),
            client.user_agent()
        );
        let io = |e: std::io::Error| err(e.to_string());
        stream.write_all(request.as_bytes()).map_err(io)?;
        stream.flush().map_err(io)?;
        let mut reader = BufReader::new(stream);
        let (status, headers) = read_head(&mut reader)?;
        if status != 101 {
            return Err(err(format!("handshake failed with HTTP {status}")));
        }
        let accept = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-accept"))
            .map(|(_, v)| v.as_str());
        if accept != Some(accept_key(&key).as_str()) {
            return Err(err("invalid Sec-WebSocket-Accept"));
        }
        Ok(WebSocket { io: reader })
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> NetResult<()> {
        let frame = encode_frame(opcode, payload, &mask_key()?);
        let s = self.io.get_mut();
        s.write_all(&frame).map_err(|e| err(e.to_string()))?;
        s.flush().map_err(|e| err(e.to_string()))
    }

    pub fn send_text(&mut self, text: &str) -> NetResult<()> {
        self.write_frame(0x1, text.as_bytes())
    }

    /// Receives the next text message, answering pings along the way.
    pub fn recv(&mut self) -> NetResult<Message> {
        let mut message = Vec::new();
        let mut in_text = false;
        loop {
            let (fin, opcode, payload) = read_frame(&mut self.io)?;
            match opcode {
                0x1 | 0x0 => {
                    if opcode == 0x1 {
                        if in_text {
                            return Err(err("new message before the previous one ended"));
                        }
                        in_text = true;
                    } else if !in_text {
                        return Err(err("unexpected continuation frame"));
                    }
                    if message.len() + payload.len() > MAX_MESSAGE {
                        return Err(err("message too large"));
                    }
                    message.extend(payload);
                    if fin {
                        return String::from_utf8(message)
                            .map(Message::Text)
                            .map_err(|_| err("non-UTF-8 text message"));
                    }
                }
                0x2 => return Err(err("unexpected binary message")),
                0x8 => return Ok(Message::Close),
                0x9 => self.write_frame(0xA, &payload)?,
                0xA => {}
                op => return Err(err(format!("unknown opcode {op}"))),
            }
        }
    }

    pub fn close(&mut self) -> NetResult<()> {
        self.write_frame(0x8, &1000u16.to_be_bytes())
    }
}

fn mask_key() -> NetResult<[u8; 4]> {
    let b = crypto::random_bytes(4).map_err(|e| err(e.to_string()))?;
    Ok([b[0], b[1], b[2], b[3]])
}

/// A masked client frame with FIN set.
pub fn encode_frame(opcode: u8, payload: &[u8], mask: &[u8; 4]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= 0xFFFF => {
            f.push(0x80 | 126);
            f.extend((n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend((n as u64).to_be_bytes());
        }
    }
    f.extend(mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// Reads one frame: (fin, opcode, unmasked payload).
pub fn read_frame(r: &mut impl Read) -> NetResult<(bool, u8, Vec<u8>)> {
    let io = |e: std::io::Error| err(e.to_string());
    let mut h = [0u8; 2];
    r.read_exact(&mut h).map_err(io)?;
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0F;
    let masked = h[1] & 0x80 != 0;
    let len = match h[1] & 0x7F {
        126 => {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).map_err(io)?;
            u64::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).map_err(io)?;
            u64::from_be_bytes(b)
        }
        n => u64::from(n),
    };
    if len > MAX_MESSAGE as u64 {
        return Err(err("frame too large"));
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).map_err(io)?;
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).map_err(io)?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok((fin, opcode, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rfc6455_accept_key() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn frame_roundtrip_all_length_forms() {
        for len in [0usize, 5, 125, 126, 300, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let frame = encode_frame(0x1, &payload, &[1, 2, 3, 4]);
            let (fin, op, got) = read_frame(&mut Cursor::new(frame)).unwrap();
            assert!(fin);
            assert_eq!(op, 1);
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn rfc6455_unmasked_server_frame() {
        // "Hello" from RFC 6455 section 5.7.
        let (fin, op, p) = read_frame(&mut Cursor::new(vec![
            0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        ]))
        .unwrap();
        assert!(fin && op == 1 && p == b"Hello");
        // Masked "Hello".
        let masked = vec![
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        assert_eq!(read_frame(&mut Cursor::new(masked)).unwrap().2, b"Hello");
        assert!(read_frame(&mut Cursor::new(vec![0x81])).is_err());
    }
}
