//! house_arrest client (SPEC Section 10.4): `VendContainer` turns the
//! service connection into an AFC session rooted at an app's container.
//! Same framing as lockdownd for the command, then AFC packets.
//!
//! Reference: libimobiledevice house_arrest.

use std::io::{Read, Write};

use super::afc::AfcClient;
use super::lockdown::{read_message_raw, write_message};
use crate::formats::plist::{Dictionary, Value};
use crate::{Error, ErrorCode, Result};

pub const SERVICE: &str = "com.apple.mobile.house_arrest";

/// Sends `VendContainer` for `bundle_id` and, on success, returns an AFC
/// client whose `/` is the app's data container.
pub fn vend_container<S: Read + Write>(mut stream: S, bundle_id: &str) -> Result<AfcClient<S>> {
    let req: Dictionary = [
        ("Command", Value::from("VendContainer")),
        ("Identifier", Value::from(bundle_id)),
    ]
    .into_iter()
    .collect();
    write_message(&mut stream, &req)?;
    let reply = read_message_raw(&mut stream)?;
    if let Some(err) = reply.get("Error").and_then(Value::as_str) {
        return Err(Error::new(
            ErrorCode::PairingFileFailed,
            format!("cannot open the app container of {bundle_id}: {err}"),
        ));
    }
    match reply.get("Status").and_then(Value::as_str) {
        Some("Complete") => Ok(AfcClient::new(stream)),
        _ => Err(Error::new(
            ErrorCode::DeviceTransportError,
            "house_arrest: unexpected VendContainer reply",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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

    fn mock(reply: &[(&str, &str)]) -> Mock {
        let d: Dictionary = reply.iter().map(|(k, v)| (*k, Value::from(*v))).collect();
        let mut bytes = Vec::new();
        write_message(&mut bytes, &d).unwrap();
        Mock {
            reply: Cursor::new(bytes),
            written: Vec::new(),
        }
    }

    #[test]
    fn vend_container_success_and_error() {
        assert!(vend_container(mock(&[("Status", "Complete")]), "com.x").is_ok());
        let err = vend_container(mock(&[("Error", "InstallationLookupFailed")]), "com.x")
            .err()
            .unwrap();
        assert_eq!(err.code, ErrorCode::PairingFileFailed);
        assert!(err.message.contains("InstallationLookupFailed"));

        let mut m = mock(&[("Status", "Complete")]);
        m = {
            let mut sent = Vec::new();
            let req: Dictionary = [
                ("Command", Value::from("VendContainer")),
                ("Identifier", Value::from("com.x")),
            ]
            .into_iter()
            .collect();
            write_message(&mut sent, &req).unwrap();
            let _ = vend_container(&mut m, "com.x").unwrap();
            assert_eq!(m.written, sent);
            m
        };
        drop(m);
    }
}
