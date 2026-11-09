//! Opt-in tests using locally acquired official libraries, never bundled/downloaded.
use sideload::anisette::local_adi::provisioning::Engine;
use sideload::pipeline::workdir::WorkDir;
use sideload_ios_core::emulation::adi::Adi;
use std::path::Path;

#[test]
#[ignore = "set SIDELOAD_AARCH64_ADI_LIBRARY_DIR to official Apple APK library directory"]
fn official_libraries_initialize_and_reject_invalid_spim() {
    let source = std::env::var_os("SIDELOAD_AARCH64_ADI_LIBRARY_DIR")
        .expect("set SIDELOAD_AARCH64_ADI_LIBRARY_DIR");
    let state = WorkDir::create(false).unwrap();
    let mut adi = Adi::open(Path::new(&source), state.path(), "0123456789abcdef").unwrap();
    assert!(!adi.is_provisioned().unwrap());
    let result = adi.start(b"invalid synthetic provisioning input");
    let error = result.unwrap_err();
    assert!(error.contains("start provisioning returned"), "{error}");
    assert!(!adi.is_provisioned().unwrap());
}

/// Explicitly opted in: provisions a new synthetic identity with Apple. No account
/// credentials are used, and generated headers/state never appear in logs.
#[test]
#[ignore = "contacts Apple; set SIDELOAD_AARCH64_ADI_LIBRARY_DIR and explicitly opt in"]
fn live_provisioning_rotation_and_persisted_provider() {
    use sideload::anisette::{AnisetteData, AnisetteProvider};
    use sideload_ios_core::local_anisette::LocalAnisette;
    let source = std::env::var_os("SIDELOAD_AARCH64_ADI_LIBRARY_DIR")
        .expect("set SIDELOAD_AARCH64_ADI_LIBRARY_DIR");
    let state = WorkDir::create(false).unwrap();
    let lib = state.path().join("anisette-local/lib");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&lib).unwrap();
    for name in ["libCoreADI.so", "libstoreservicescore.so"] {
        std::fs::copy(Path::new(&source).join(name), lib.join(name)).unwrap();
    }
    fn field<'a>(data: &'a AnisetteData, name: &str) -> &'a str {
        data.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .expect("missing header")
    }
    fn validate(data: &AnisetteData) {
        for name in [
            "X-Apple-I-MD",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-RINFO",
            "X-Apple-I-MD-LU",
            "X-Mme-Device-Id",
            "X-Mme-Client-Info",
            "X-Apple-I-Client-Time",
            "X-Apple-I-TimeZone",
            "X-Apple-Locale",
        ] {
            assert!(
                !field(data, name).is_empty(),
                "required Anisette header is empty"
            );
        }
        for name in ["X-Apple-I-MD", "X-Apple-I-MD-M"] {
            assert!(
                !sideload::formats::base64::decode(field(data, name))
                    .expect("invalid header encoding")
                    .is_empty()
            );
        }
    }
    eprintln!("interpreted ADI live: initialize and provision a fresh synthetic identity");
    let mut provider = LocalAnisette::new(state.path()).unwrap();
    let first = provider.headers().unwrap();
    validate(&first);
    eprintln!("interpreted ADI live: first header generation succeeded");
    let again = provider.headers().unwrap();
    validate(&again);
    assert!(
        field(&first, "X-Apple-I-MD-M") == field(&again, "X-Apple-I-MD-M"),
        "machine identity changed"
    );
    drop(provider);
    eprintln!("interpreted ADI live: reopen provider using committed provisioning state");
    let mut provider = LocalAnisette::new(state.path()).unwrap();
    let resumed = provider.headers().unwrap();
    validate(&resumed);
    assert!(
        field(&first, "X-Apple-I-MD-M") == field(&resumed, "X-Apple-I-MD-M"),
        "saved identity was not reused"
    );
    eprintln!("interpreted ADI live: wait 35 seconds for OTP rotation");
    std::thread::sleep(std::time::Duration::from_secs(35));
    let later = provider.headers().unwrap();
    validate(&later);
    assert!(
        field(&first, "X-Apple-I-MD") != field(&later, "X-Apple-I-MD"),
        "OTP did not rotate"
    );
    drop(provider);
    let request = sideload::formats::json::Value::object([
        (
            "op",
            sideload::formats::json::Value::from("prepare_anisette"),
        ),
        (
            "config",
            sideload::formats::json::Value::object([
                (
                    "data_dir",
                    sideload::formats::json::Value::from(state.path().to_str().unwrap()),
                ),
                (
                    "anisette_mode",
                    sideload::formats::json::Value::from("local"),
                ),
                (
                    "anisette_server",
                    sideload::formats::json::Value::from("ftp://unused.invalid"),
                ),
            ]),
        ),
    ])
    .to_string();
    let reply =
        sideload_ios_core::api::handle(&request, &mut || panic!("must not ask for credentials"));
    let reply = sideload::formats::json::parse(&reply).unwrap();
    assert!(
        reply.get("ok").and_then(|v| v.as_bool()) == Some(true),
        "credential-free local check failed"
    );
    assert!(
        reply
            .get("result")
            .and_then(|v| v.get("ready"))
            .and_then(|v| v.as_bool())
            == Some(true)
    );
    assert!(reply.get("headers").is_none());
    eprintln!(
        "interpreted ADI live: headers, OTP rotation, persisted state and credential-free API passed"
    );
}
