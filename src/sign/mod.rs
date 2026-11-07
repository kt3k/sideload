//! In-process iOS code signing (SPEC 11.2).
//!
//! `sign_bundle` accepts a signing identity and an Apple-issued CMS profile for
//! each app/extension identifier. Frameworks and dylibs are signed before their
//! containing bundle; profiles are embedded only in apps/extensions. No Apple
//! account or device calls are made here. `install` orchestration is separate.
pub mod apple_certs;
pub mod cms;
pub mod code_directory;
pub mod code_resources;
pub mod entitlements;
pub mod macho;
pub mod requirements;

use crate::{
    Error, ErrorCode, Result,
    bundle::AppBundle,
    crypto::rsa_keygen::RsaPrivateKey,
    formats::plist::{self, Dictionary, Value},
    pipeline::Phase,
};
use code_directory::{HashType, blob};
use code_resources::NestedCode;
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
pub type SignResult<T> = std::result::Result<T, String>;
pub(crate) fn fail(message: impl Into<String>) -> String {
    message.into()
}

pub struct SigningIdentity {
    /// DER signer certificate first, followed by intermediate certificates.
    pub certificates: Vec<Vec<u8>>,
    pub private_key: RsaPrivateKey,
    pub team_id: String,
}
impl SigningIdentity {
    /// Builds an identity whose certificate set is the Apple-issued
    /// `certificate` followed by its WWDR intermediate (when known) and the
    /// Apple Root CA, so that iOS can build the full chain.
    pub fn with_apple_chain(
        certificate: Vec<u8>,
        private_key: RsaPrivateKey,
        team_id: String,
    ) -> Self {
        SigningIdentity {
            certificates: apple_certs::chain_for(certificate),
            private_key,
            team_id,
        }
    }
}
impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningIdentity")
            .field("team_id", &self.team_id)
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}
fn error(path: &Path, message: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::SigningFailed,
        format!("{}: {message}", path.display()),
    )
    .with_phase(Phase::Signing)
}
fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| error(path, e))
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(error(path, "refusing to write through symlink"));
    }
    fs::write(path, bytes).map_err(|e| error(path, e))
}
fn safe_relative(name: &str) -> bool {
    !name.is_empty()
        && Path::new(name).components().count() == 1
        && Path::new(name)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
fn requirement_text(identifier: &str, team: &str) -> String {
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
        quote(identifier),
        quote(team)
    )
}
/// Sign one Mach-O, including every architecture in a universal binary.
/// Info.plist/CodeResources bytes must already be final before this call.
pub fn sign_macho(
    data: &[u8],
    identifier: &str,
    identity: &SigningIdentity,
    info: Option<&[u8]>,
    resources: Option<&[u8]>,
    entitlements: Option<&Dictionary>,
) -> SignResult<(Vec<u8>, NestedCode)> {
    let mut special = BTreeMap::new();
    if let Some(info) = info {
        special.insert(1, info.to_vec());
    }
    special.insert(2, requirements::designated(identifier, &identity.team_id)?);
    if let Some(resources) = resources {
        special.insert(3, resources.to_vec());
    }
    if let Some(e) = entitlements {
        special.insert(5, blob(0xfade7171, &entitlements::xml(e)));
        special.insert(7, blob(0xfade7172, &entitlements::encode_der(e)?));
    }
    let mut seal = None;
    let out = macho::sign_slices(data, |mut prepared| {
        if prepared.executable_segment.2 != 0 {
            if let Some(e) = entitlements {
                prepared.executable_segment.2 |= entitlements::executable_flags(e);
            }
        }
        // Both directory lengths and RSA signature length are stable once the
        // load command fields are reserved. Compute exact capacity in two passes.
        let make = |prepared: &macho::Prepared| -> SignResult<(Vec<u8>, Vec<u8>)> {
            let primary = code_directory::build(
                &prepared.code,
                identifier,
                &identity.team_id,
                &special,
                HashType::Sha1,
                prepared.executable_segment,
            )?;
            let alternate = code_directory::build(
                &prepared.code,
                identifier,
                &identity.team_id,
                &special,
                HashType::Sha256,
                prepared.executable_segment,
            )?;
            let cms = cms::sign(
                &primary,
                &[
                    (HashType::Sha1, primary.clone()),
                    (HashType::Sha256, alternate.clone()),
                ],
                &identity.certificates,
                &identity.private_key,
            )?;
            let mut slots = BTreeMap::from([
                (0, primary),
                (0x1000, alternate.clone()),
                (0x10000, blob(0xfade0b01, &cms)),
            ]);
            for slot in [2, 5, 7] {
                if let Some(b) = special.get(&slot) {
                    slots.insert(slot, b.clone());
                }
            }
            Ok((
                code_directory::superblob(0xfade0cc0, &slots)?,
                code_directory::cdhash(&alternate, HashType::Sha256),
            ))
        };
        let capacity = make(&prepared)?.0.len();
        prepared.reserve(capacity)?;
        let (signature, hash) = make(&prepared)?;
        if signature.len() != capacity {
            return Err(fail("signature size changed after reservation"));
        }
        seal = Some(NestedCode {
            cdhash: hash,
            requirement: requirement_text(identifier, &identity.team_id),
        });
        prepared.finish(&signature, capacity)
    })?;
    Ok((
        out,
        seal.ok_or_else(|| fail("Mach-O contains no architectures"))?,
    ))
}

/// Sign a prepared bundle in place. Each map value is the complete, unmodified
/// mobileprovision returned for that exact bundle identifier. This method does
/// not roll back the working directory on failure; callers must discard it.
pub fn sign_bundle(
    app: &AppBundle,
    identity: &SigningIdentity,
    profiles: &BTreeMap<String, Vec<u8>>,
    thread_count: usize,
) -> Result<()> {
    if thread_count == 0 {
        return Err(error(&app.path, "thread_count must be positive"));
    }
    let leaf = identity
        .certificates
        .first()
        .ok_or_else(|| error(&app.path, "no signing certificate"))?;
    cms::validate_identity(leaf, &identity.private_key).map_err(|e| error(&app.path, e))?;
    // Validate all profiles before any bundle is modified.
    let mut derived = BTreeMap::new();
    for b in app.all_bundles_inner_first() {
        let id = b
            .bundle_identifier()
            .map_err(|e| error(&b.path, e.message))?;
        let raw = profiles
            .get(id)
            .ok_or_else(|| error(&b.path, format!("missing profile for {id}")))?;
        let p = entitlements::profile_plist(raw).map_err(|e| error(&b.path, e))?;
        let certificates = p
            .get("DeveloperCertificates")
            .and_then(Value::as_array)
            .ok_or_else(|| error(&b.path, "profile has no DeveloperCertificates"))?;
        if !certificates
            .iter()
            .any(|c| c.as_data() == Some(leaf.as_slice()))
        {
            return Err(error(
                &b.path,
                "signing certificate is not authorized by profile",
            ));
        }
        derived.insert(
            id.to_owned(),
            entitlements::derive(&p, id, &identity.team_id).map_err(|e| error(&b.path, e))?,
        );
    }
    sign_directory(&app.path, identity, profiles, &derived, thread_count, true)?;
    Ok(())
}
fn sign_directory(
    root: &Path,
    identity: &SigningIdentity,
    profiles: &BTreeMap<String, Vec<u8>>,
    derived: &BTreeMap<String, Dictionary>,
    threads: usize,
    needs_profile: bool,
) -> Result<NestedCode> {
    let info_path = root.join("Info.plist");
    let info = read(&info_path)?;
    let plist = plist::from_bytes(&info).map_err(|e| error(&info_path, e))?;
    let id = plist
        .get("CFBundleIdentifier")
        .and_then(Value::as_str)
        .ok_or_else(|| error(&info_path, "missing CFBundleIdentifier"))?;
    let executable = plist
        .get("CFBundleExecutable")
        .and_then(Value::as_str)
        .filter(|s| safe_relative(s))
        .ok_or_else(|| error(&info_path, "invalid CFBundleExecutable"))?;
    let exe = root.join(executable);
    if fs::symlink_metadata(&exe)
        .map_err(|e| error(&exe, e))?
        .file_type()
        .is_symlink()
    {
        return Err(error(&exe, "symlink executables are unsupported"));
    }
    let mut nested = BTreeMap::new();
    let mut binaries = Vec::new();
    collect_code(
        root,
        root,
        &exe,
        &mut binaries,
        &mut nested,
        identity,
        profiles,
        derived,
        threads,
    )?;
    // Independent dylibs can run concurrently. A single shared counter caps the
    // number of workers; all children finish before their parent's resource seal.
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads.min(binaries.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = binaries.get(i) else { break };
                    let result = (|| {
                        let bytes = read(path)?;
                        let (signed, seal) = sign_macho(&bytes, id, identity, None, None, None)
                            .map_err(|e| error(path, e))?;
                        write(path, &signed)?;
                        Ok((path.clone(), seal))
                    })();
                    results.lock().unwrap().push((i, result));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    for (_, r) in results {
        let (path, seal) = r?;
        nested.insert(relative(root, &path)?, seal);
    }
    let ents = if needs_profile {
        let raw = profiles
            .get(id)
            .ok_or_else(|| error(root, format!("missing profile for {id}")))?;
        write(&root.join("embedded.mobileprovision"), raw)?;
        Some(
            derived
                .get(id)
                .ok_or_else(|| error(root, "missing derived entitlements"))?,
        )
    } else {
        None
    };
    let resources = code_resources::build(root, executable, &nested).map_err(|e| error(root, e))?;
    let signature_dir = root.join("_CodeSignature");
    if let Ok(meta) = fs::symlink_metadata(&signature_dir) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(error(&signature_dir, "invalid signature directory"));
        }
        fs::remove_dir_all(&signature_dir).map_err(|e| error(&signature_dir, e))?;
    }
    fs::create_dir(&signature_dir).map_err(|e| error(&signature_dir, e))?;
    write(&signature_dir.join("CodeResources"), &resources)?;
    let bytes = read(&exe)?;
    let (signed, seal) = sign_macho(&bytes, id, identity, Some(&info), Some(&resources), ents)
        .map_err(|e| error(&exe, e))?;
    write(&exe, &signed)?;
    Ok(seal)
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .map(|s| s.replace(std::path::MAIN_SEPARATOR, "/"))
        .ok_or_else(|| error(path, "invalid nested code path"))
}
#[allow(clippy::too_many_arguments)]
fn collect_code(
    root: &Path,
    dir: &Path,
    exe: &Path,
    binaries: &mut Vec<PathBuf>,
    nested: &mut BTreeMap<String, NestedCode>,
    identity: &SigningIdentity,
    profiles: &BTreeMap<String, Vec<u8>>,
    derived: &BTreeMap<String, Dictionary>,
    threads: usize,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .map_err(|e| error(dir, e))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| error(dir, e))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path == exe || entry.file_name() == "_CodeSignature" {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| error(&path, e))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            match path.extension().and_then(|e| e.to_str()) {
                Some("app" | "appex" | "framework") => {
                    let needs = path.extension().is_some_and(|e| e != "framework");
                    let seal = sign_directory(&path, identity, profiles, derived, threads, needs)?;
                    nested.insert(relative(root, &path)?, seal);
                }
                _ => collect_code(
                    root, &path, exe, binaries, nested, identity, profiles, derived, threads,
                )?,
            }
        } else if meta.is_file() {
            use std::io::Read;
            let mut magic = [0; 4];
            let mut f = fs::File::open(&path).map_err(|e| error(&path, e))?;
            if f.read(&mut magic).map_err(|e| error(&path, e))? == 4 {
                // A fat magic is only code if the architecture table checks out
                // (Java class files share 0xCAFEBABE); otherwise it is a resource.
                let is_code = macho::is_thin_macho(&magic)
                    || (macho::is_fat_magic(&magic) && macho::looks_like_fat_macho(&read(&path)?));
                if is_code {
                    binaries.push(path);
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;
