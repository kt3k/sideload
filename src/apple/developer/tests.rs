use super::*;
use crate::{
    anisette::AnisetteData,
    net::{NetError, NetResult, http::Response},
    pipeline::workdir::WorkDir,
};
use std::{cell::RefCell, rc::Rc};
struct Anisette;
impl AnisetteProvider for Anisette {
    fn headers(&mut self) -> Result<AnisetteData> {
        Ok(AnisetteData {
            headers: vec![("X-Apple-I-MD", "fresh-otp")]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        })
    }
}
fn dict(p: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Dictionary(Dictionary::from_iter(p))
}
fn app() -> Value {
    dict([
        ("appIdId", "APP".into()),
        ("identifier", "com.test".into()),
        ("name", "Test".into()),
        ("features", Value::Dictionary(Dictionary::new())),
    ])
}
fn group() -> Value {
    dict([
        ("applicationGroup", "GROUP".into()),
        ("identifier", "group.com.test".into()),
        ("name", "Group".into()),
    ])
}
fn device() -> Value {
    dict([
        ("deviceId", "DEVICE".into()),
        ("deviceNumber", "UDID".into()),
        ("name", "Phone".into()),
    ])
}
#[derive(Default)]
struct Log {
    calls: Vec<(String, Value)>,
    reply: Option<Value>,
    fail: bool,
}
struct Wire(Rc<RefCell<Log>>);
impl Transport for Wire {
    fn send(&mut self, r: &Request) -> NetResult<Response> {
        let mut log = self.0.borrow_mut();
        if log.fail {
            return Err(NetError::transport("secret should not escape"));
        }
        assert_eq!(r.method, "POST");
        assert!(r.url.starts_with(BASE));
        assert!(
            r.headers
                .iter()
                .any(|(k, v)| k == "X-Apple-GS-Token" && v == "TOKEN")
        );
        assert!(
            r.headers
                .iter()
                .any(|(k, v)| k == "X-Apple-I-Identity-Id" && v == "1234")
        );
        assert!(
            r.headers
                .iter()
                .any(|(k, v)| k == "X-Apple-I-MD" && v == "fresh-otp")
        );
        let p = plist::from_bytes(&r.body).unwrap();
        assert_eq!(
            p.get("clientId").and_then(Value::as_str),
            Some("XABBG36SBA")
        );
        assert_eq!(
            p.get("protocolVersion").and_then(Value::as_str),
            Some("QH65B2")
        );
        assert_eq!(
            p.get("requestId").and_then(Value::as_str).unwrap().len(),
            36
        );
        let op = r
            .url
            .split('/')
            .next_back()
            .unwrap()
            .split('.')
            .next()
            .unwrap()
            .to_owned();
        if op != "listTeams" {
            assert!(r.url.contains("/ios/"));
            assert_eq!(p.get("teamId").and_then(Value::as_str), Some("TEAM"));
        } else {
            assert!(!r.url.contains("/ios/"));
        }
        log.calls.push((op.clone(), p.clone()));
        let reply = if let Some(reply) = log.reply.clone() {
            reply
        } else {
            let mut d = Dictionary::from_iter([("resultCode", 0i64)]);
            match op.as_str() {
                "listTeams" => {
                    d.insert(
                        "teams",
                        Value::Array(vec![dict([
                            ("teamId", "TEAM".into()),
                            ("name", "Team".into()),
                        ])]),
                    );
                }
                "listDevices" => {
                    d.insert("devices", Value::Array(vec![device()]));
                }
                "addDevice" => {
                    d.insert("device", device());
                }
                "listAllDevelopmentCerts" => {
                    d.insert(
                        "certificates",
                        Value::Array(vec![dict([
                            ("serialNumber", "SERIAL".into()),
                            ("certificateId", "CERT".into()),
                            ("machineName", "Sideloader".into()),
                            ("certContent", Value::Data(vec![1, 2, 3])),
                        ])]),
                    );
                }
                "submitDevelopmentCSR" => {
                    assert_eq!(
                        p.get("machineName").and_then(Value::as_str),
                        Some("Sideloader")
                    );
                    d.insert(
                        "certRequest",
                        dict([("certRequestId", "CERTREQUEST".into())]),
                    );
                }
                "listAppIds" => {
                    d.insert("appIds", Value::Array(vec![app()]));
                    d.insert("availableQuantity", 9i64);
                    d.insert("maxQuantity", 10i64);
                }
                "addAppId" | "updateAppId" => {
                    d.insert("appId", app());
                }
                "listApplicationGroups" => {
                    d.insert("applicationGroupList", Value::Array(vec![group()]));
                }
                "addApplicationGroup" => {
                    d.insert("applicationGroup", group());
                }
                "downloadTeamProvisioningProfile" => {
                    d.insert(
                        "provisioningProfile",
                        dict([
                            ("appIdId", "APP".into()),
                            ("encodedProfile", Value::Data(vec![1, 2, 3])),
                            ("UUID", "PROFILE".into()),
                        ]),
                    );
                }
                "deleteDevice"
                | "deleteAppId"
                | "revokeDevelopmentCert"
                | "assignApplicationGroupToAppId" => {}
                _ => panic!("unknown operation {op}"),
            };
            Value::Dictionary(d)
        };
        Ok(Response {
            status: 200,
            headers: vec![],
            body: reply.to_xml(),
            url: r.url.clone(),
        })
    }
}
fn client(log: &Rc<RefCell<Log>>) -> Developer<Wire> {
    Developer::with_transport(
        Session {
            adsid: "1234".into(),
            token: "TOKEN".into(),
            expiry: None,
        },
        Box::new(Anisette),
        Wire(log.clone()),
    )
}
#[test]
fn all_developer_operations_use_expected_wire_fields() {
    let log = Rc::new(RefCell::new(Log::default()));
    let mut c = client(&log);
    assert_eq!(c.select_team(None).unwrap().team_id, "TEAM");
    assert_eq!(
        c.select_team(Some("missing")).unwrap_err().code,
        ErrorCode::TeamNotFound
    );
    assert_eq!(c.list_devices("TEAM").unwrap()[0].udid, "UDID");
    c.add_device("TEAM", "Phone", "UDID").unwrap();
    c.delete_device("TEAM", "DEVICE").unwrap();
    assert_eq!(
        c.list_development_certs("TEAM").unwrap()[0].content,
        Some(vec![1, 2, 3])
    );
    assert_eq!(
        c.submit_development_csr("TEAM", "CSR").unwrap(),
        "CERTREQUEST"
    );
    c.revoke_development_cert("TEAM", "SERIAL").unwrap();
    let apps = c.list_app_ids("TEAM").unwrap();
    assert_eq!(apps.available_quantity, Some(9));
    assert_eq!(apps.max_quantity, Some(10));
    c.add_app_id("TEAM", "com.test", "Test").unwrap();
    c.update_app_id("TEAM", "APP", Dictionary::from_iter([("APG3427HIY", true)]))
        .unwrap();
    c.delete_app_id("TEAM", "APP").unwrap();
    assert_eq!(
        c.list_app_groups("TEAM").unwrap()[0].application_group,
        "GROUP"
    );
    c.add_app_group("TEAM", "group.com.test", "Group").unwrap();
    c.assign_app_group("TEAM", "APP", "GROUP").unwrap();
    assert_eq!(
        c.download_team_provisioning_profile("TEAM", "APP")
            .unwrap()
            .encoded_profile,
        vec![1, 2, 3]
    );
    let l = log.borrow();
    for (op, p) in &l.calls {
        match op.as_str() {
            "deleteDevice" => assert_eq!(p.get("deviceId").and_then(Value::as_str), Some("DEVICE")),
            "revokeDevelopmentCert" => assert_eq!(
                p.get("serialNumber").and_then(Value::as_str),
                Some("SERIAL")
            ),
            "updateAppId" => assert_eq!(p.get("APG3427HIY").and_then(Value::as_bool), Some(true)),
            "assignApplicationGroupToAppId" => assert_eq!(
                p.get("applicationGroups").and_then(Value::as_str),
                Some("GROUP")
            ),
            _ => {}
        }
    }
}
#[test]
fn errors_are_not_hidden_by_partial_payloads_and_no_retry() {
    let log = Rc::new(RefCell::new(Log {
        reply: Some(dict([
            ("resultCode", 9412i64.into()),
            ("userString", "maximum App ID limit TOKEN".into()),
            ("appId", app()),
        ])),
        ..Default::default()
    }));
    let e = client(&log)
        .add_app_id("TEAM", "com.test", "Test")
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::AppIdQuotaExceeded);
    assert!(e.message.contains("9412"));
    assert!(!e.message.contains("TOKEN"));
    assert_eq!(log.borrow().calls.len(), 1);
    log.borrow_mut().fail = true;
    assert_eq!(
        client(&log).list_teams().unwrap_err().code,
        ErrorCode::AppleTransportError
    );
    log.borrow_mut().fail = false;
    log.borrow_mut().reply = Some(dict([("resultCode", 0i64.into())]));
    assert_eq!(
        client(&log).list_devices("TEAM").unwrap_err().code,
        ErrorCode::AppleApiError
    );
}
#[test]
fn profile_id_and_feature_identity_are_checked() {
    let log = Rc::new(RefCell::new(Log::default()));
    let mut c = client(&log);
    assert_eq!(
        c.download_team_provisioning_profile("TEAM", "OTHER")
            .unwrap_err()
            .code,
        ErrorCode::ProfileDownloadFailed
    );
    let before = log.borrow().calls.len();
    assert!(
        c.update_app_id("TEAM", "APP", Dictionary::from_iter([("teamId", "OTHER")]))
            .is_err()
    );
    assert_eq!(log.borrow().calls.len(), before);
}
#[test]
fn openssl_verifies_generated_csr() {
    use std::process::Command;
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipped: openssl unavailable");
        return;
    }
    let key = crate::crypto::rsa_keygen::RsaPrivateKey::from_pem(include_str!(
        "../../crypto/testdata/openssl_key.pem"
    ))
    .unwrap();
    let csr = make_csr(&key, "Sideloader").unwrap();
    let d = WorkDir::create(false).unwrap();
    std::fs::write(d.path().join("request.pem"), csr).unwrap();
    let output = Command::new("openssl")
        .args(["req", "-verify", "-noout", "-in"])
        .arg(d.path().join("request.pem"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
