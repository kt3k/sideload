//! misagent client (SPEC Section 10.3 step 4): install provisioning
//! profiles on the device. Same length-prefixed XML plist framing as
//! lockdownd.

use std::io::{Read, Write};

use super::lockdown::{read_message_raw, write_message};
use crate::formats::plist::{Dictionary, Value};
use crate::{Error, ErrorCode, Result};

pub const SERVICE: &str = "com.apple.misagent";

fn transport_err(msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::DeviceTransportError, format!("misagent: {msg}"))
}

pub struct MisagentClient<S> {
    stream: S,
}

impl<S: Read + Write> MisagentClient<S> {
    pub fn new(stream: S) -> MisagentClient<S> {
        MisagentClient { stream }
    }

    fn transact(&mut self, req: &Dictionary) -> Result<Dictionary> {
        write_message(&mut self.stream, req)?;
        read_message_raw(&mut self.stream)
    }

    fn check_status(reply: &Dictionary) -> Result<()> {
        match reply.get("Status").and_then(Value::as_u64) {
            Some(0) => Ok(()),
            Some(code) => Err(transport_err(format!("returned status {code}"))),
            None => Err(transport_err("reply has no integer Status")),
        }
    }

    /// Installs a `.mobileprovision` profile.
    pub fn install(&mut self, profile: &[u8]) -> Result<()> {
        let req: Dictionary = [
            ("MessageType", Value::from("Install")),
            ("Profile", Value::Data(profile.to_vec())),
            ("ProfileType", Value::from("Provisioning")),
        ]
        .into_iter()
        .collect();
        Self::check_status(&self.transact(&req)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::lockdown::write_message;
    use std::io::Cursor;

    fn framed(d: Dictionary) -> Vec<u8> {
        let mut b = Vec::new();
        write_message(&mut b, &d).unwrap();
        b
    }

    struct Mock {
        reply: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for Mock {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(buf)
        }
    }
    impl Write for Mock {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn install_success_and_failure() {
        let ok: Dictionary = [("Status", Value::Integer(0.into()))].into_iter().collect();
        let mut client = MisagentClient::new(Mock {
            reply: Cursor::new(framed(ok)),
            written: Vec::new(),
        });
        assert!(client.install(b"profile-bytes").is_ok());
        // The request carried the profile as Data with ProfileType Provisioning.
        let sent = crate::device::lockdown::read_message_raw(&mut Cursor::new(
            client.stream.written.clone(),
        ))
        .unwrap();
        assert_eq!(sent.get("MessageType").unwrap().as_str(), Some("Install"));
        assert_eq!(
            sent.get("Profile").unwrap().as_data(),
            Some(&b"profile-bytes"[..])
        );
        assert_eq!(
            sent.get("ProfileType").unwrap().as_str(),
            Some("Provisioning")
        );

        let bad: Dictionary = [("Status", Value::Integer(203.into()))]
            .into_iter()
            .collect();
        let mut client = MisagentClient::new(Mock {
            reply: Cursor::new(framed(bad)),
            written: Vec::new(),
        });
        assert_eq!(
            client.install(b"x").unwrap_err().code,
            ErrorCode::DeviceTransportError
        );
    }
}
