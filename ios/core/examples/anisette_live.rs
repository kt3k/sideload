//! Opt-in Apple provisioning probe. Never logs OTPs, machine IDs or blobs.
use sideload::anisette::local_adi::provisioning::{self, Identity};
use sideload_ios_core::emulation::adi::Adi;
use std::path::PathBuf;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let libraries = PathBuf::from(
        args.next()
            .ok_or("usage: anisette_live LIBRARY_DIR STATE_DIR")?,
    );
    let state = PathBuf::from(args.next().ok_or("missing STATE_DIR")?);
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&state)?;
    let identity = Identity::load(&state)?;
    eprintln!("interpreted ADI: initializing official libraries");
    let mut adi = Adi::open(&libraries, &state, &identity.android_id)?;
    let mut transport = sideload::apple::Https::new()?;
    eprintln!("interpreted ADI: provisioning with Apple and requesting headers");
    let first = provisioning::headers(&identity, &mut adi, &mut transport)?;
    assert!(
        first
            .headers
            .iter()
            .any(|(k, v)| k == "X-Apple-I-MD" && !v.is_empty())
    );
    eprintln!("interpreted ADI: generated required headers successfully");
    Ok(())
}
