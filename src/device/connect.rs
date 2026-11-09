//! How the Device Client reaches a device port: through usbmuxd (the CLI,
//! SPEC Section 10) or over TCP to a network address (the on-device app,
//! `ios/SPEC.md` Section 3.3, where the address is the loopback VPN peer).

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::usbmuxd::{Socket, Usbmuxd};
use crate::{Error, ErrorCode, Result};

/// Opens a connection to a port on one device.
pub trait Connector {
    fn connect(&self, port: u16) -> Result<Socket>;
}

/// A device attached to usbmuxd.
pub struct Usbmux {
    pub device_id: u32,
}

impl Connector for Usbmux {
    fn connect(&self, port: u16) -> Result<Socket> {
        Usbmuxd::connect()?.connect_to_device(self.device_id, port)
    }
}

/// A device reachable at `host` over TCP.
#[derive(Debug, Clone)]
pub struct Tcp {
    pub host: String,
    pub connect_timeout: Duration,
    /// Read/write timeout of established connections.
    pub io_timeout: Option<Duration>,
}

impl Tcp {
    pub fn new(host: impl Into<String>) -> Tcp {
        Tcp {
            host: host.into(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Some(Duration::from_secs(120)),
        }
    }
}

fn tcp_err(host: &str, port: u16, e: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::DeviceTransportError,
        format!("cannot connect to {host}:{port} ({e}); is the loopback VPN turned on?"),
    )
}

impl Connector for Tcp {
    fn connect(&self, port: u16) -> Result<Socket> {
        let addrs: Vec<_> = (self.host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| tcp_err(&self.host, port, e))?
            .collect();
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    stream
                        .set_read_timeout(self.io_timeout)
                        .and_then(|()| stream.set_write_timeout(self.io_timeout))
                        .map_err(|e| tcp_err(&self.host, port, e))?;
                    return Ok(Socket::Tcp(stream));
                }
                Err(e) => last = Some(e),
            }
        }
        Err(match last {
            Some(e) => tcp_err(&self.host, port, e),
            None => tcp_err(&self.host, port, "no address"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn tcp_connects_to_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"hi").unwrap();
        });
        let mut socket = Tcp::new("127.0.0.1").connect(port).unwrap();
        let mut buf = [0u8; 2];
        socket.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        server.join().unwrap();
    }

    #[test]
    fn tcp_failure_names_host_and_vpn() {
        // Bind then drop to get a port that refuses connections.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let Err(err) = Tcp::new("127.0.0.1").connect(port) else {
            panic!("connected to a closed port")
        };
        assert_eq!(err.code, ErrorCode::DeviceTransportError);
        assert!(err.message.contains("127.0.0.1"), "{}", err.message);
        assert!(err.message.contains("VPN"), "{}", err.message);
    }
}
