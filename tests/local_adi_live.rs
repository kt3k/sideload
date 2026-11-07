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
use std::time::Duration;

/// Longer than one OTP time window (about 30 seconds).
const OTP_WINDOW_WAIT: Duration = Duration::from_secs(35);

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
    eprintln!("live ADI: requesting a second OTP immediately");
    let again = provider.headers().unwrap();
    let otp = |data: sideload::anisette::AnisetteData| {
        data.headers
            .into_iter()
            .find(|(name, _)| name == "X-Apple-I-MD")
            .unwrap()
            .1
    };
    let first = otp(first);
    let again = otp(again);
    assert!(!first.is_empty() && !again.is_empty());
    // OTPs are time-windowed: back-to-back requests may return the same
    // value, so only a request after the window has passed must differ.
    eprintln!("live ADI: waiting {OTP_WINDOW_WAIT:?} for the next OTP window");
    std::thread::sleep(OTP_WINDOW_WAIT);
    let later = otp(provider.headers().unwrap());
    assert!(!later.is_empty());
    assert!(
        later != first,
        "the OTP must change after {OTP_WINDOW_WAIT:?}"
    );
    eprintln!("live ADI: OTP requests succeeded and the OTP rotates");
}
