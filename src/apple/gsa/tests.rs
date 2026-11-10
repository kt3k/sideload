use super::*;
use crate::{
    anisette::AnisetteData,
    crypto::{hmac_sha256, pbkdf2_sha256, sha256, sha256_parts},
    net::{NetResult, http::Response},
};
use num_bigint::BigUint;
use std::{cell::RefCell, rc::Rc};
struct Anisette;
impl AnisetteProvider for Anisette {
    fn headers(&mut self) -> Result<AnisetteData> {
        Ok(AnisetteData {
            headers: vec![(
                "X-Mme-Client-Info".into(),
                crate::anisette::local_adi::provisioning::ANDROID_CLIENT_INFO.into(),
            )],
        })
    }
}
#[derive(Default)]
struct Server {
    protocol: &'static str,
    key: Vec<u8>,
    a: Vec<u8>,
    b: Vec<u8>,
    m1: Vec<u8>,
    proof: Vec<u8>,
    two_factor: bool,
    verified: bool,
    wrong: usize,
    resends: usize,
    operations: Vec<String>,
    tamper: bool,
}
struct Wire(Rc<RefCell<Server>>);
fn dict(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Dictionary(Dictionary::from_iter(pairs))
}
fn ok_status() -> Value {
    dict([("ec", 0i64.into())])
}
fn spd() -> Value {
    dict([
        ("adsid", "1234".into()),
        ("GsIdmsToken", "idms-secret".into()),
        ("sk", Value::Data(vec![7; 32])),
        ("c", Value::Data(vec![8; 16])),
    ])
}
fn padded(v: &BigUint) -> Vec<u8> {
    let raw = v.to_bytes_be();
    let mut p = vec![0; 256 - raw.len()];
    p.extend(raw);
    p
}
const GROUP: &str = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73";
impl Server {
    fn challenge(&mut self, a: &[u8], user: &str) -> Value {
        let n = BigUint::parse_bytes(GROUP.as_bytes(), 16).unwrap();
        let g = BigUint::from(2u32);
        let salt = vec![5; 16];
        let b = BigUint::from(4321u32);
        let hashed = sha256(b"password");
        let password = if self.protocol == "s2k_fo" {
            crypto::hex(&hashed).into_bytes()
        } else {
            hashed.to_vec()
        };
        let pw = pbkdf2_sha256(&password, &salt, 100).unwrap();
        let x = BigUint::from_bytes_be(&sha256_parts(&[&salt, &sha256_parts(&[b":", &pw])]));
        let v = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&sha256_parts(&[&padded(&n), &padded(&g)]));
        let big_b = (&k * &v + g.modpow(&b, &n)) % &n;
        let b_bytes = big_b.to_bytes_be();
        let a_num = BigUint::from_bytes_be(a);
        let u = BigUint::from_bytes_be(&sha256_parts(&[&padded(&a_num), &padded(&big_b)]));
        let secret = ((&a_num * v.modpow(&u, &n)) % &n).modpow(&b, &n);
        let key = sha256(&secret.to_bytes_be());
        let xor: Vec<u8> = sha256(&n.to_bytes_be())
            .iter()
            .zip(sha256(&padded(&g)))
            .map(|(a, b)| a ^ b)
            .collect();
        let m1 = sha256_parts(&[&xor, &sha256(user.as_bytes()), &salt, a, &b_bytes, &key]);
        self.proof = sha256_parts(&[a, &m1, &key]).to_vec();
        self.key = key.to_vec();
        self.m1 = m1.to_vec();
        self.a = a.to_vec();
        self.b = b_bytes.clone();
        dict([
            ("Status", ok_status()),
            ("sp", self.protocol.into()),
            ("s", Value::Data(salt)),
            ("i", 100i64.into()),
            ("B", Value::Data(b_bytes)),
            ("c", "context".into()),
        ])
    }
}
impl Transport for Wire {
    fn send(&mut self, r: &Request) -> NetResult<Response> {
        let mut s = self.0.borrow_mut();
        assert!(r.headers.iter().any(|(k, v)| k == "X-Mme-Client-Info"
            && v == crate::anisette::local_adi::provisioning::ANDROID_CLIENT_INFO));
        let p = if r.url == LOOKUP {
            dict([(
                "urls",
                dict([
                    ("gsService", "https://gsa.apple.com/service".into()),
                    (
                        "trustedDeviceSecondaryAuth",
                        "https://gsa.apple.com/trusted".into(),
                    ),
                    ("validateCode", "https://gsa.apple.com/validate".into()),
                ]),
            )])
        } else if r.url.ends_with("/trusted") {
            s.resends += 1;
            ok_status()
        } else if r.url.ends_with("/validate") {
            let c = &r
                .headers
                .iter()
                .find(|(k, _)| k == "security-code")
                .unwrap()
                .1;
            if c == "123456" {
                s.verified = true;
                ok_status()
            } else {
                s.wrong += 1;
                dict([("ec", (-21669i64).into()), ("em", "incorrect code".into())])
            }
        } else {
            let body = plist::from_bytes(&r.body).unwrap();
            let req = body.get("Request").unwrap();
            assert_eq!(
                req.get("cpd")
                    .and_then(|v| v.get("X-Mme-Client-Info"))
                    .and_then(Value::as_str),
                Some(crate::anisette::local_adi::provisioning::ANDROID_CLIENT_INFO)
            );
            let op = string(req, "o").unwrap();
            s.operations.push(op.into());
            let response = match op {
                "init" => {
                    assert_eq!(string(req, "u").unwrap(), "user@example.com");
                    s.challenge(data(req, "A2k").unwrap(), "user@example.com")
                }
                "complete" => {
                    assert_eq!(data(req, "M1").unwrap(), s.m1);
                    let key = hmac_sha256(&s.key, &[b"extra data key:"]);
                    let iv = hmac_sha256(&s.key, &[b"extra data iv:"]);
                    let encrypted = cbc::encrypt(&key, &iv[..16], &spd().to_xml()).unwrap();
                    let mut status = Dictionary::from_iter([("ec", 0i64)]);
                    if s.two_factor && !s.verified {
                        status.insert("au", "trustedDeviceSecondaryAuth");
                    }
                    let mut proof = s.proof.clone();
                    if s.tamper {
                        proof[0] ^= 1;
                    }
                    dict([
                        ("Status", Value::Dictionary(status)),
                        ("M2", Value::Data(proof)),
                        ("spd", Value::Data(encrypted)),
                    ])
                }
                "apptokens" => {
                    assert_eq!(string(req, "t").unwrap(), "idms-secret");
                    assert_eq!(
                        data(req, "checksum").unwrap(),
                        hmac_sha256(&[7; 32], &[b"apptokens", b"1234", APP.as_bytes()])
                    );
                    let token = dict([
                        ("status-code", 200i64.into()),
                        (
                            "t",
                            dict([(
                                APP,
                                dict([
                                    ("token", "xcode-secret".into()),
                                    ("expiry", 12345i64.into()),
                                ]),
                            )]),
                        ),
                    ]);
                    let mut et = b"XYZ".to_vec();
                    et.extend([6; 16]);
                    et.extend(gcm::encrypt(&[7; 32], &[6; 16], b"XYZ", &token.to_xml()).unwrap());
                    dict([("Status", ok_status()), ("et", Value::Data(et))])
                }
                _ => panic!("operation"),
            };
            dict([("Response", response)])
        };
        Ok(Response {
            status: 200,
            headers: vec![],
            body: p.to_xml(),
            url: r.url.clone(),
        })
    }
}
#[test]
fn srp_login_and_app_token_both_protocols() {
    for protocol in ["s2k", "s2k_fo"] {
        let server = Rc::new(RefCell::new(Server {
            protocol,
            ..Default::default()
        }));
        let mut g = Gsa::with_transport(Box::new(Anisette), Wire(server.clone()));
        let session = g
            .authenticate("User@Example.com", "password", &mut || {
                panic!("no 2FA expected")
            })
            .unwrap();
        assert_eq!(session.adsid, "1234");
        assert_eq!(session.token, "xcode-secret");
        assert!(!format!("{session:?}").contains("xcode-secret"));
        assert_eq!(
            server.borrow().operations,
            ["init", "complete", "apptokens"]
        );
    }
}
#[test]
fn two_factor_wrong_code_resend_and_relogin() {
    let server = Rc::new(RefCell::new(Server {
        protocol: "s2k",
        two_factor: true,
        ..Default::default()
    }));
    let mut g = Gsa::with_transport(Box::new(Anisette), Wire(server.clone()));
    let mut answers = vec![
        CodeInput::Code("000000".into()),
        CodeInput::Resend,
        CodeInput::Code("123456".into()),
    ]
    .into_iter();
    g.authenticate("USER@EXAMPLE.COM", "password", &mut || {
        Ok(answers.next().unwrap())
    })
    .unwrap();
    let s = server.borrow();
    assert_eq!(s.wrong, 1);
    assert_eq!(s.resends, 2);
    assert_eq!(
        s.operations,
        ["init", "complete", "init", "complete", "apptokens"]
    );
}
#[test]
fn rejects_invalid_proof_and_token_tampering() {
    let server = Rc::new(RefCell::new(Server {
        protocol: "s2k",
        tamper: true,
        ..Default::default()
    }));
    let mut g = Gsa::with_transport(Box::new(Anisette), Wire(server));
    assert!(
        g.authenticate("user@example.com", "password", &mut || panic!())
            .unwrap_err()
            .message
            .contains("proof mismatch")
    );
    let mut et = b"XYZ".to_vec();
    et.extend([1; 16]);
    et.extend(
        gcm::encrypt(
            &[2; 32],
            &[1; 16],
            b"XYZ",
            &dict([("ok", true.into())]).to_xml(),
        )
        .unwrap(),
    );
    et[20] ^= 1;
    assert!(decrypt_token(&et, &[2; 32]).is_err());
    assert!(endpoint("https://evil.example/auth").is_err());
    assert!(endpoint("http://gsa.apple.com/auth").is_err());
}
#[test]
fn apple_error_redacts_credentials() {
    let r = dict([(
        "Status",
        dict([("ec", (-1i64).into()), ("em", "bad password token".into())]),
    )]);
    let e = check(&r, &["password", "token"], ErrorCode::LoginFailed).unwrap_err();
    assert!(e.message.contains("-1"));
    assert!(!e.message.contains("password"));
    assert!(!e.message.contains("token"));
}
