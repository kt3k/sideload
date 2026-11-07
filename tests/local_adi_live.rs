//! Explicit opt-in integration check; never prints generated anisette values.
#![cfg(any(
    target_os = "macos",
    all(any(target_os = "linux", windows), target_arch = "x86_64")
))]
use sideload::{
    anisette::{AnisetteProvider, local_adi::LocalAdi},
    pipeline::workdir::WorkDir,
};
#[cfg(not(target_os = "macos"))]
use std::path::Path;

#[test]
#[ignore = "contacts Apple provisioning servers; set SIDELOAD_ADI_LIBRARY_DIR"]
fn local_adi_live_provisioning_and_otp() {
    let dir = WorkDir::create(false).unwrap();
    #[cfg(not(target_os = "macos"))]
    {
        let source =
            std::env::var_os("SIDELOAD_ADI_LIBRARY_DIR").expect("set SIDELOAD_ADI_LIBRARY_DIR");
        let lib = dir.path().join("lib");
        std::fs::create_dir(&lib).unwrap();
        for name in ["libstoreservicescore.so", "libCoreADI.so"] {
            std::fs::copy(Path::new(&source).join(name), lib.join(name)).unwrap();
        }
    }
    eprintln!("live ADI: initializing official libraries");
    let mut provider = LocalAdi::new(dir.path()).unwrap();
    eprintln!("live ADI: provisioning and requesting first OTP");
    let first = provider.headers().unwrap();
    eprintln!("live ADI: requesting second OTP");
    let second = provider.headers().unwrap();
    let otp = |data: sideload::anisette::AnisetteData| {
        data.headers
            .into_iter()
            .find(|(name, _)| name == "X-Apple-I-MD")
            .unwrap()
            .1
    };
    let first = otp(first);
    let second = otp(second);
    assert!(!first.is_empty() && !second.is_empty());
    #[cfg(not(target_os = "macos"))]
    assert!(
        first != second,
        "successive Android ADI OTP values must differ"
    );
    eprintln!("live ADI: two OTP requests succeeded");
}
