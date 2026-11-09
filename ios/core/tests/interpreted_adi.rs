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
