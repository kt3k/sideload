//! installation_proxy client (SPEC Section 10.3 step 5): install a staged
//! developer app and report progress. Same framing as lockdownd.

use std::io::{Read, Write};

use super::lockdown::{read_message_raw, write_message};
use crate::formats::plist::{Dictionary, Value};
use crate::{Error, ErrorCode, Result};

pub const SERVICE: &str = "com.apple.mobile.installation_proxy";

fn install_err(msg: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::InstallFailed,
        format!("installation_proxy: {msg}"),
    )
}

fn transport_err(msg: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::DeviceTransportError,
        format!("installation_proxy: {msg}"),
    )
}

pub struct InstallationProxyClient<S> {
    stream: S,
}

impl<S: Read + Write> InstallationProxyClient<S> {
    pub fn new(stream: S) -> InstallationProxyClient<S> {
        InstallationProxyClient { stream }
    }

    /// Installs the app staged at `remote_path` (an AFC path under
    /// `PublicStaging`). `PackageType` is `Developer`. `progress` is called
    /// with the percentage and the current status string as the device
    /// reports them.
    pub fn install(
        &mut self,
        remote_path: &str,
        mut progress: impl FnMut(u64, &str),
    ) -> Result<()> {
        let options: Dictionary = [("PackageType", Value::from("Developer"))]
            .into_iter()
            .collect();
        let req: Dictionary = [
            ("Command", Value::from("Install")),
            ("PackagePath", Value::from(remote_path)),
            ("ClientOptions", Value::Dictionary(options)),
        ]
        .into_iter()
        .collect();
        write_message(&mut self.stream, &req)?;

        loop {
            let reply = read_message_raw(&mut self.stream)?;
            // Any of Error / ErrorDescription marks a failed install
            // (SPEC Section 10.3); print whichever fields are present.
            if reply.contains_key("Error") || reply.contains_key("ErrorDescription") {
                let text = |k: &str| -> Option<String> {
                    match reply.get(k)? {
                        Value::String(s) => Some(s.clone()),
                        Value::Integer(i) => Some(i.to_string()),
                        _ => None,
                    }
                };
                let err = text("Error").unwrap_or_else(|| "(none)".to_owned());
                let desc =
                    text("ErrorDescription").unwrap_or_else(|| "installation failed".to_owned());
                return Err(install_err(match text("ErrorDetail") {
                    Some(d) => format!("{desc} [{err}: {d}]"),
                    None => format!("{desc} [{err}]"),
                }));
            }
            let percent = reply
                .get("PercentComplete")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            match reply.get("Status").and_then(Value::as_str) {
                Some("Complete") => return Ok(()),
                Some(status) => progress(percent, status),
                None => return Err(transport_err("progress reply has no Status")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::lockdown::{read_message_raw, write_message};
    use std::collections::VecDeque;
    use std::io::Cursor;

    struct Mock {
        replies: VecDeque<Vec<u8>>,
        current: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Mock {
        fn new(replies: Vec<Dictionary>) -> Mock {
            Mock {
                replies: replies
                    .into_iter()
                    .map(|d| {
                        let mut b = Vec::new();
                        write_message(&mut b, &d).unwrap();
                        b
                    })
                    .collect(),
                current: Cursor::new(Vec::new()),
                written: Vec::new(),
            }
        }
    }
    impl Read for Mock {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.current.position() as usize >= self.current.get_ref().len() {
                if let Some(next) = self.replies.pop_front() {
                    self.current = Cursor::new(next);
                }
            }
            self.current.read(buf)
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

    fn reply(pairs: &[(&str, Value)]) -> Dictionary {
        pairs.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    #[test]
    fn install_reports_progress_then_completes() {
        let replies = vec![
            reply(&[
                ("PercentComplete", Value::Integer(25.into())),
                ("Status", Value::from("CreatingStagingDirectory")),
            ]),
            reply(&[
                ("PercentComplete", Value::Integer(90.into())),
                ("Status", Value::from("Installing")),
            ]),
            reply(&[("Status", Value::from("Complete"))]),
        ];
        let mut client = InstallationProxyClient::new(Mock::new(replies));
        let mut seen = Vec::new();
        client
            .install("PublicStaging/App.app", |p, s| seen.push((p, s.to_owned())))
            .unwrap();
        assert_eq!(
            seen,
            [
                (25, "CreatingStagingDirectory".to_owned()),
                (90, "Installing".to_owned())
            ]
        );

        // The request named the package and PackageType Developer.
        let sent = read_message_raw(&mut Cursor::new(client.stream.written.clone())).unwrap();
        assert_eq!(sent.get("Command").unwrap().as_str(), Some("Install"));
        assert_eq!(
            sent.get("PackagePath").unwrap().as_str(),
            Some("PublicStaging/App.app")
        );
        assert_eq!(
            sent.get("ClientOptions")
                .unwrap()
                .get("PackageType")
                .unwrap()
                .as_str(),
            Some("Developer")
        );
    }

    #[test]
    fn install_surfaces_device_error() {
        let replies = vec![reply(&[
            ("Error", Value::from("ApplicationVerificationFailed")),
            (
                "ErrorDescription",
                Value::from("Failed to verify code signature"),
            ),
        ])];
        let mut client = InstallationProxyClient::new(Mock::new(replies));
        let err = client
            .install("PublicStaging/App.app", |_, _| {})
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InstallFailed);
        assert!(err.message.contains("verify code signature"));
        assert!(err.message.contains("ApplicationVerificationFailed"));
    }

    #[test]
    fn error_only_reply_is_install_failed() {
        let replies = vec![reply(&[("Error", Value::from("APIInternalError"))])];
        let mut client = InstallationProxyClient::new(Mock::new(replies));
        let err = client
            .install("PublicStaging/App.app", |_, _| {})
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InstallFailed);
        assert!(err.message.contains("APIInternalError"));
    }
}
