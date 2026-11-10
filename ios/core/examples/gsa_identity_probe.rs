//! Opt-in SRP-init probe with a reserved .invalid identity. No password, M1,
//! 2FA, real account or returned challenge/header values are logged or used.
use sideload::{
    anisette::{AnisetteData, AnisetteProvider},
    apple::{Https, Transport},
    crypto::srp::SrpClient,
    formats::plist::{self, Dictionary, Value},
    net::http::{Request, Url},
    pipeline::workdir::WorkDir,
};
use sideload_ios_core::local_anisette::LocalAnisette;
use std::path::PathBuf;
const LEGACY: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
fn request(
    transport: &mut Https,
    mut request: Request,
    data: &AnisetteData,
) -> Result<(u16, Option<Value>), Box<dyn std::error::Error>> {
    let url = Url::parse(&request.url).map_err(|_| "invalid probe endpoint")?;
    if !url.tls || url.port != 443 || !(url.host == "apple.com" || url.host.ends_with(".apple.com"))
    {
        return Err("refusing non-Apple endpoint".into());
    }
    request.headers.extend(data.headers.clone());
    request = request
        .header("Content-Type", "text/x-xml-plist")
        .header("Accept", "text/x-xml-plist")
        .header("X-Apple-App-Info", "com.apple.gs.xcode.auth")
        .header("X-Xcode-Version", "15.0 (15A240d)")
        .max_body(4 * 1024 * 1024);
    let response = transport
        .send(&request)
        .map_err(|_| "probe transport failed (no response values logged)")?;
    Ok((response.status, plist::from_bytes(&response.body).ok()))
}
fn probe(
    label: &str,
    provider: &mut LocalAnisette,
    legacy: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut transport = Https::new()?;
    let mut data = provider.headers()?;
    if legacy {
        for (name, value) in &mut data.headers {
            if name == "X-Mme-Client-Info" {
                *value = LEGACY.into();
            }
        }
    }
    let (http, lookup) = request(
        &mut transport,
        Request::get("https://gsa.apple.com/grandslam/GsService2/lookup"),
        &data,
    )?;
    let Some(service) = lookup
        .as_ref()
        .and_then(|v| v.get("urls"))
        .and_then(|v| v.get("gsService"))
        .and_then(Value::as_str)
    else {
        eprintln!("SRP init {label}: lookup HTTP {http}, no service URL");
        return Ok(false);
    };
    let cpd = sideload::apple::gsa::client_provisioning_data(&data)?;
    let srp = SrpClient::new()?;
    let body = Value::Dictionary(Dictionary::from_iter([
        (
            "Header",
            Value::Dictionary(Dictionary::from_iter([("Version", "1.0.1")])),
        ),
        (
            "Request",
            Value::Dictionary(Dictionary::from_iter([
                ("A2k", Value::Data(srp.public_ephemeral())),
                ("cpd", Value::Dictionary(cpd)),
                ("o", Value::from("init")),
                ("ps", Value::Array(vec!["s2k".into(), "s2k_fo".into()])),
                ("u", Value::from("sideload-auth-probe@example.invalid")),
            ])),
        ),
    ]));
    let (http, response) = request(&mut transport, Request::post(service, body.to_xml()), &data)?;
    let response = response.as_ref().and_then(|v| v.get("Response"));
    let status = response.and_then(|v| v.get("Status").or(Some(v)));
    let ec = status.and_then(|v| v.get("ec")).and_then(Value::as_i64);
    let challenge = response.is_some_and(|v| {
        ["B", "s", "i", "c", "sp"]
            .iter()
            .all(|key| v.get(key).is_some())
    });
    eprintln!("SRP init {label}: HTTP {http}, Apple code {ec:?}, challenge={challenge}");
    Ok(http == 200 && ec == Some(0) && challenge)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let libraries = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: gsa_identity_probe AARCH64_LIBRARY_DIR")?,
    );
    let state = WorkDir::create(false)?;
    let lib = state.path().join("anisette-local/lib");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&lib)?;
    for name in ["libCoreADI.so", "libstoreservicescore.so"] {
        std::fs::copy(libraries.join(name), lib.join(name))?;
    }
    let mut provider = LocalAnisette::new(state.path())?;
    eprintln!("SRP init probe: synthetic .invalid identity; no password or proof is sent");
    let _legacy = probe("legacy-mac", &mut provider, true)?;
    if !probe("android", &mut provider, false)? {
        return Err(
            "Android SRP init did not return an accepted challenge; sign-in remains unverified"
                .into(),
        );
    }
    eprintln!(
        "SRP init probe: Android profile reached an accepted challenge; full account login is not tested"
    );
    Ok(())
}
