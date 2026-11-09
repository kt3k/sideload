//! Explicit developer probe. No vendor libraries are bundled or downloaded here.
use sideload_ios_core::emulation::runtime::Runtime;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: adi_probe LIBRARY_DIR")?;
    let core = std::fs::read(format!("{dir}/libCoreADI.so"))?;
    let store = std::fs::read(format!("{dir}/libstoreservicescore.so"))?;
    let mut runtime = Runtime::new(&core, &store)?;
    let path = runtime.c_string("/adi")?;
    let id = runtime.c_string("0123456789abcdef")?;
    for (name, args) in [
        ("kq56gsgHG6", vec![path]),
        ("nf92ngaK92", vec![path]),
        ("Sph98paBcz", vec![id, 16]),
        ("aslgmuibau", vec![u64::MAX - 1]),
    ] {
        match runtime.call(name, &args, 50_000_000) {
            Ok(value) => println!("{name}: {}", value as u32 as i32),
            Err(error) => {
                eprintln!("{name}: {error}; import={:?}", runtime.import_at(error.pc));
                return Err(error.into());
            }
        }
    }
    Ok(())
}
