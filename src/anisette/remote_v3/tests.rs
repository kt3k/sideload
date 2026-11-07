use super::*;
use crate::net::NetError;
use crate::pipeline::workdir::WorkDir;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
#[derive(Default)]
struct Log {
    requests: Vec<Request>,
    sent: Vec<json::Value>,
    sockets: usize,
    closed: usize,
    replies: VecDeque<json::Value>,
    messages: Option<Vec<Message>>,
    client_info: Option<json::Value>,
    lookup: Option<Value>,
    fail_http: bool,
}
struct Fake(Rc<RefCell<Log>>);
struct Socket {
    log: Rc<RefCell<Log>>,
    messages: VecDeque<Message>,
}
fn j(pairs: impl IntoIterator<Item = (&'static str, json::Value)>) -> json::Value {
    json::Value::object(pairs)
}
fn headers(otp: &str) -> json::Value {
    j([
        ("result", "Headers".into()),
        ("X-Apple-I-MD", base64::encode(otp.as_bytes()).into()),
        ("X-Apple-I-MD-M", base64::encode(b"machine").into()),
        ("X-Apple-I-MD-RINFO", "17106176".into()),
    ])
}
fn invalidated() -> json::Value {
    j([
        ("result", "GetHeadersError".into()),
        ("message", "error -45061".into()),
    ])
}
fn messages() -> Vec<Message> {
    vec![
        j([("result", "GiveIdentifier".into())]),
        j([("result", "GiveStartProvisioningData".into())]),
        j([
            ("result", "GiveEndProvisioningData".into()),
            ("cpim", base64::encode(b"cpim").into()),
        ]),
        j([
            ("result", "ProvisioningSuccess".into()),
            ("adi_pb", base64::encode(b"private ADI state").into()),
        ]),
    ]
    .into_iter()
    .map(|v| Message::Text(v.to_string()))
    .collect()
}
impl Transport for Fake {
    fn http(&mut self, r: &Request) -> NetResult<Response> {
        let mut l = self.0.borrow_mut();
        l.requests.push(r.clone());
        if l.fail_http {
            return Err(NetError::transport("secret response must not be logged"));
        }
        assert!(
            !r.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        );
        let body = if r.url.ends_with("/v3/client_info") {
            assert_eq!(r.method, "GET");
            l.client_info
                .clone()
                .unwrap_or_else(|| {
                    j([
                        ("client_info", "<MacBook> <Mac OS X> <AuthKit>".into()),
                        ("user_agent", "akd/1.0".into()),
                    ])
                })
                .to_string()
                .into_bytes()
        } else if r.url == LOOKUP {
            assert_eq!(r.method, "GET");
            l.lookup
                .clone()
                .unwrap_or_else(|| {
                    Value::Dictionary(Dictionary::from_iter([(
                        "urls",
                        Value::Dictionary(Dictionary::from_iter([
                            (
                                "midStartProvisioning",
                                Value::from("https://gsa.apple.com/start"),
                            ),
                            (
                                "midFinishProvisioning",
                                Value::from("https://gsa.apple.com/finish"),
                            ),
                        ])),
                    )]))
                })
                .to_xml()
        } else if r.url == "https://gsa.apple.com/start" || r.url == "https://gsa.apple.com/finish"
        {
            assert_eq!(r.method, "POST");
            let p = plist::from_bytes(&r.body).unwrap();
            assert!(p.get("Header").unwrap().as_dict().unwrap().is_empty());
            assert!(
                r.headers
                    .iter()
                    .any(|(k, v)| k == "User-Agent" && v == "akd/1.0")
            );
            let response = if r.url.ends_with("/start") {
                assert!(p.get("Request").unwrap().as_dict().unwrap().is_empty());
                Dictionary::from_iter([("spim", Value::from(base64::encode(b"spim")))])
            } else {
                assert_eq!(
                    p.get("Request").unwrap().get("cpim").unwrap().as_str(),
                    Some(base64::encode(b"cpim").as_str())
                );
                Dictionary::from_iter([
                    ("ptm", Value::from(base64::encode(b"ptm"))),
                    ("tk", Value::from(base64::encode(b"tk"))),
                ])
            };
            Value::Dictionary(Dictionary::from_iter([(
                "Response",
                Value::Dictionary(response),
            )]))
            .to_xml()
        } else if r.url.ends_with("/v3/get_headers") {
            assert_eq!(r.method, "POST");
            let p = json::parse(std::str::from_utf8(&r.body).unwrap()).unwrap();
            assert_eq!(
                base64::decode(field(&p, "identifier").unwrap())
                    .unwrap()
                    .len(),
                16
            );
            assert!(
                !base64::decode(field(&p, "adi_pb").unwrap())
                    .unwrap()
                    .is_empty()
            );
            l.replies
                .pop_front()
                .unwrap_or_else(|| headers("fresh otp"))
                .to_string()
                .into_bytes()
        } else {
            panic!("unexpected request {}", r.url)
        };
        Ok(Response {
            status: 200,
            headers: vec![],
            body,
            url: r.url.clone(),
        })
    }
    fn websocket(&mut self, url: &str) -> NetResult<Box<dyn Session>> {
        assert!(url.ends_with("/v3/provisioning_session"));
        assert!(url.starts_with("ws://") || url.starts_with("wss://"));
        let mut log = self.0.borrow_mut();
        log.sockets += 1;
        let messages = log.messages.clone().unwrap_or_else(messages).into();
        Ok(Box::new(Socket {
            log: self.0.clone(),
            messages,
        }))
    }
}
impl Session for Socket {
    fn recv(&mut self) -> NetResult<Message> {
        self.messages
            .pop_front()
            .ok_or_else(|| NetError::transport("EOF"))
    }
    fn send(&mut self, text: &str) -> NetResult<()> {
        self.log.borrow_mut().sent.push(json::parse(text).unwrap());
        Ok(())
    }
    fn close(&mut self) -> NetResult<()> {
        self.log.borrow_mut().closed += 1;
        Ok(())
    }
}
fn provider(dir: &Path, log: &Rc<RefCell<Log>>) -> RemoteV3 {
    RemoteV3::with_transport("http://localhost:6969/", dir, Box::new(Fake(log.clone()))).unwrap()
}
fn header<'a>(data: &'a AnisetteData, key: &str) -> &'a str {
    &data.headers.iter().find(|(k, _)| k == key).unwrap().1
}
#[test]
fn provisions_persists_reuses_and_refreshes_headers() {
    let dir = WorkDir::create(false).unwrap();
    let log = Rc::new(RefCell::new(Log::default()));
    log.borrow_mut().replies =
        VecDeque::from([headers("first"), headers("second"), headers("third")]);
    let mut p = provider(dir.path(), &log);
    let first = p.headers().unwrap();
    let second = p.headers().unwrap();
    assert_ne!(
        header(&first, "X-Apple-I-MD"),
        header(&second, "X-Apple-I-MD")
    );
    assert_eq!(log.borrow().sockets, 1);
    assert_eq!(log.borrow().closed, 1);
    assert_eq!(log.borrow().sent.len(), 3);
    let state = State::parse(&fs::read(p.state_path()).unwrap()).unwrap();
    assert_eq!(
        state.adi_pb.as_deref(),
        Some(b"private ADI state".as_slice())
    );
    assert_eq!(header(&first, "X-Apple-I-MD-LU"), state.local_user_id());
    assert_eq!(header(&first, "X-Mme-Device-Id"), state.device_id());
    assert_eq!(header(&first, "X-Apple-I-TimeZone"), "UTC");
    assert_eq!(header(&first, "X-Apple-I-SRL-NO"), "0");
    assert_eq!(
        base64::decode(field(&log.borrow().sent[0], "identifier").unwrap()).unwrap(),
        state.identifier
    );
    let mut restarted = provider(dir.path(), &log);
    let third = restarted.headers().unwrap();
    assert_eq!(log.borrow().sockets, 1);
    assert_eq!(
        header(&third, "X-Mme-Device-Id"),
        header(&first, "X-Mme-Device-Id")
    );
    assert!(!format!("{first:?} {p:?}").contains("private ADI state"));
    assert!(!format!("{first:?}").contains(&base64::encode(b"first")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(p.state_path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(p.state_path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let other =
        RemoteV3::with_transport("https://another.example", dir.path(), Box::new(Fake(log)))
            .unwrap();
    assert_ne!(p.state_path(), other.state_path());
}
#[test]
fn invalidation_retries_once_preserving_identifier() {
    let dir = WorkDir::create(false).unwrap();
    let log = Rc::new(RefCell::new(Log::default()));
    let mut p = provider(dir.path(), &log);
    p.headers().unwrap();
    let device = p.state.as_ref().unwrap().identifier;
    log.borrow_mut().replies = VecDeque::from([invalidated(), headers("recovered")]);
    p.headers().unwrap();
    assert_eq!(log.borrow().sockets, 2);
    assert_eq!(p.state.as_ref().unwrap().identifier, device);
    log.borrow_mut().replies = VecDeque::from([invalidated(), invalidated()]);
    let e = p.headers().unwrap_err();
    assert_eq!(e.code, ErrorCode::AnisetteUnavailable);
    assert_eq!(log.borrow().sockets, 3);
    assert!(e.message.contains("after one reset"));
}
#[test]
fn rejects_broken_sessions_without_persisting() {
    for bad in [
        Message::Close,
        Message::Text("{".into()),
        Message::Text(
            j([
                ("result", "ProvisioningSuccess".into()),
                ("adi_pb", "bad".into()),
            ])
            .to_string(),
        ),
        Message::Text(
            j([
                ("result", "StartProvisioningError".into()),
                ("message", "SECRET".into()),
            ])
            .to_string(),
        ),
    ] {
        let dir = WorkDir::create(false).unwrap();
        let log = Rc::new(RefCell::new(Log {
            messages: Some(vec![bad]),
            ..Default::default()
        }));
        let mut p = provider(dir.path(), &log);
        let e = p.headers().unwrap_err();
        assert_eq!(e.code, ErrorCode::AnisetteUnavailable);
        assert!(!e.message.contains("SECRET"));
        assert!(!p.state_path().exists());
    }
}
#[test]
fn rejects_invalid_state_info_headers_and_lookup() {
    let dir = WorkDir::create(false).unwrap();
    let log = Rc::new(RefCell::new(Log::default()));
    let mut p = provider(dir.path(), &log);
    p.state_directories(true).unwrap();
    fs::write(p.state_path(), b"broken").unwrap();
    assert!(p.headers().is_err());
    assert_eq!(log.borrow().sockets, 0);
    fs::remove_file(p.state_path()).unwrap();
    for bad in [
        "http://evil.example/start",
        "https://apple.com.evil.example/start",
        "https://gsa.apple.com:8443/start",
    ] {
        assert!(RemoteV3::apple_endpoint(Some(&Value::from(bad))).is_err());
    }
    assert!(RemoteV3::new("http://localhost?key=secret", dir.path()).is_err());
    let log = Rc::new(RefCell::new(Log {
        client_info: Some(j([
            ("client_info", "bad\r\nInjected: x".into()),
            ("user_agent", "ok".into()),
        ])),
        ..Default::default()
    }));
    assert!(provider(dir.path(), &log).headers().is_err());
    let log = Rc::new(RefCell::new(Log {
        fail_http: true,
        ..Default::default()
    }));
    let e = provider(dir.path(), &log).headers().unwrap_err();
    assert!(!e.message.contains("secret response"));
    let log = Rc::new(RefCell::new(Log::default()));
    log.borrow_mut().replies.push_back(j([
        ("result", "Headers".into()),
        ("X-Apple-I-MD", "bad\r\n".into()),
        ("X-Apple-I-MD-M", "YQ==".into()),
        ("X-Apple-I-MD-RINFO", "1".into()),
    ]));
    assert!(provider(dir.path(), &log).headers().is_err());
    assert!(
        State::parse(
            &Value::Dictionary(Dictionary::from_iter([(
                "keychain_identifier",
                Value::Data(vec![0; 15])
            )]))
            .to_xml()
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn refuses_symlink_state_directory_before_creating_files() {
    use std::os::unix::fs::symlink;
    let dir = WorkDir::create(false).unwrap();
    let outside = WorkDir::create(false).unwrap();
    symlink(outside.path(), dir.path().join("anisette")).unwrap();
    let log = Rc::new(RefCell::new(Log::default()));
    let e = provider(dir.path(), &log).headers().unwrap_err();
    assert_eq!(e.code, ErrorCode::AnisetteUnavailable);
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    assert_eq!(log.borrow().sockets, 0);
}
