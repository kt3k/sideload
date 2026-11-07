use super::*;
use crate::{
    net::{NetResult, http::Response},
    pipeline::workdir::WorkDir,
};
struct Native {
    ready: bool,
    destroyed: usize,
    fail: bool,
    otps: u8,
}
impl Engine for Native {
    fn is_provisioned(&mut self) -> AdiResult<bool> {
        Ok(self.ready)
    }
    fn start(&mut self, spim: &[u8]) -> AdiResult<(Vec<u8>, u32)> {
        assert_eq!(spim, b"spim");
        Ok((b"cpim".to_vec(), 7))
    }
    fn finish(&mut self, s: u32, ptm: &[u8], tk: &[u8]) -> AdiResult<()> {
        assert_eq!(s, 7);
        assert_eq!(ptm, b"ptm");
        assert_eq!(tk, b"tk");
        if self.fail {
            return Err("fixture failure".into());
        }
        self.ready = true;
        Ok(())
    }
    fn destroy(&mut self, s: u32) {
        assert_eq!(s, 7);
        self.destroyed += 1;
    }
    fn otp(&mut self) -> AdiResult<(Vec<u8>, Vec<u8>)> {
        self.otps += 1;
        Ok((b"mid".to_vec(), vec![self.otps]))
    }
}
struct Wire {
    calls: usize,
}
impl Transport for Wire {
    fn send(&mut self, r: &Request) -> NetResult<Response> {
        self.calls += 1;
        assert!(r.headers.iter().any(|(k, _)| k == "X-Mme-Device-Id"));
        let response = if self.calls == 1 {
            Value::Dictionary(Dictionary::from_iter([(
                "urls",
                Value::Dictionary(Dictionary::from_iter([
                    ("midStartProvisioning", "https://gsa.apple.com/start"),
                    ("midFinishProvisioning", "https://gsa.apple.com/end"),
                ])),
            )]))
        } else {
            let request = plist::from_bytes(&r.body).unwrap();
            let d = if self.calls == 2 {
                assert!(
                    request
                        .get("Request")
                        .and_then(Value::as_dict)
                        .unwrap()
                        .is_empty()
                );
                Dictionary::from_iter([("spim", base64::encode(b"spim"))])
            } else {
                assert_eq!(
                    request
                        .get("Request")
                        .unwrap()
                        .get("cpim")
                        .and_then(Value::as_str),
                    Some(base64::encode(b"cpim").as_str())
                );
                Dictionary::from_iter([
                    ("ptm", base64::encode(b"ptm")),
                    ("tk", base64::encode(b"tk")),
                ])
            };
            Value::Dictionary(Dictionary::from_iter([("Response", Value::Dictionary(d))]))
        };
        Ok(Response {
            status: 200,
            headers: vec![],
            body: response.to_xml(),
            url: r.url.clone(),
        })
    }
}
#[test]
fn identity_reuse_provision_once_fresh_otps() {
    let d = WorkDir::create(false).unwrap();
    let id = Identity::load(d.path()).unwrap();
    assert_eq!(id.device_id, Identity::load(d.path()).unwrap().device_id);
    let mut engine = Native {
        ready: false,
        destroyed: 0,
        fail: false,
        otps: 0,
    };
    let mut wire = Wire { calls: 0 };
    let a = headers(&id, &mut engine, &mut wire).unwrap();
    let b = headers(&id, &mut engine, &mut wire).unwrap();
    assert_eq!(wire.calls, 3);
    assert_eq!(engine.destroyed, 0);
    assert_ne!(
        a.headers.iter().find(|(k, _)| k == "X-Apple-I-MD"),
        b.headers.iter().find(|(k, _)| k == "X-Apple-I-MD")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(d.path().join("device.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn destroy_provisioning_session_on_failure() {
    let d = WorkDir::create(false).unwrap();
    let id = Identity::load(d.path()).unwrap();
    let mut engine = Native {
        ready: false,
        destroyed: 0,
        fail: true,
        otps: 0,
    };
    assert!(headers(&id, &mut engine, &mut Wire { calls: 0 }).is_err());
    assert_eq!(engine.destroyed, 1);
    assert_eq!(engine.otps, 0);
}
#[test]
fn malformed_identity_not_silently_replaced() {
    let d = WorkDir::create(false).unwrap();
    fs::write(d.path().join("device.json"), b"invalid").unwrap();
    assert!(Identity::load(d.path()).is_err());
    assert_eq!(fs::read(d.path().join("device.json")).unwrap(), b"invalid");
}
