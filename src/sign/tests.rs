use super::*;
use crate::{
    crypto::{sha1, sha256},
    formats::{base64, der},
};
use std::process::Command;
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "sideload-sign-{}-{}",
            std::process::id(),
            crate::crypto::hex(&crate::crypto::random_bytes(8).unwrap())
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn identity() -> SigningIdentity {
    let b64: String = include_str!("testdata/certificate.pem")
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    SigningIdentity {
        certificates: vec![base64::decode(&b64).unwrap()],
        private_key: RsaPrivateKey::from_pem(include_str!("../crypto/testdata/openssl_key.pem"))
            .unwrap(),
        team_id: "TEAM".into(),
    }
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn get32(b: &[u8], p: usize) -> usize {
    u32::from_be_bytes(b[p..p + 4].try_into().unwrap()) as usize
}
fn thin(wide: bool) -> Vec<u8> {
    let mut b = vec![0; 8192];
    put32(&mut b, 0, if wide { 0xfeedfacf } else { 0xfeedface });
    put32(&mut b, 4, if wide { 0x100000c } else { 12 });
    put32(&mut b, 8, 0);
    put32(&mut b, 12, 2);
    put32(&mut b, 16, 2);
    let h = if wide { 32 } else { 28 };
    let seg = if wide { 72 } else { 56 };
    let sec = if wide { 80 } else { 68 };
    put32(&mut b, 20, (2 * seg + sec) as u32);
    put32(&mut b, h, if wide { 0x19 } else { 1 });
    put32(&mut b, h + 4, (seg + sec) as u32);
    b[h + 8..h + 14].copy_from_slice(b"__TEXT");
    if wide {
        put64(&mut b, h + 24, 0x100000000);
        put64(&mut b, h + 32, 4096);
        put64(&mut b, h + 48, 4096);
        put32(&mut b, h + 64, 1);
        put64(&mut b, h + seg + 40, 16);
        put32(&mut b, h + seg + 48, 512);
    } else {
        put32(&mut b, h + 24, 0x1000);
        put32(&mut b, h + 28, 4096);
        put32(&mut b, h + 36, 4096);
        put32(&mut b, h + 48, 1);
        put32(&mut b, h + seg + 36, 16);
        put32(&mut b, h + seg + 40, 512);
    }
    let p = h + seg + sec;
    put32(&mut b, p, if wide { 0x19 } else { 1 });
    put32(&mut b, p + 4, seg as u32);
    b[p + 8..p + 18].copy_from_slice(b"__LINKEDIT");
    if wide {
        put64(&mut b, p + 24, 0x100001000);
        put64(&mut b, p + 32, 4096);
        put64(&mut b, p + 40, 4096);
        put64(&mut b, p + 48, 4096);
    } else {
        put32(&mut b, p + 24, 0x2000);
        put32(&mut b, p + 28, 4096);
        put32(&mut b, p + 32, 4096);
        put32(&mut b, p + 36, 4096);
    }
    b[512..528].copy_from_slice(b"test machinecode");
    b
}
fn signature(data: &[u8]) -> &[u8] {
    let wide = data[..4] == [0xcf, 0xfa, 0xed, 0xfe];
    let mut p = if wide { 32 } else { 28 };
    for _ in 0..u32::from_le_bytes(data[16..20].try_into().unwrap()) {
        let c = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
        if c == 0x1d {
            let off = u32::from_le_bytes(data[p + 8..p + 12].try_into().unwrap()) as usize;
            return &data[off..];
        }
        p += u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap()) as usize;
    }
    panic!("no signature")
}
fn slot(sig: &[u8], wanted: usize) -> &[u8] {
    for i in 0..get32(sig, 8) {
        let p = 12 + 8 * i;
        if get32(sig, p) == wanted {
            let off = get32(sig, p + 4);
            return &sig[off..off + get32(sig, off + 4)];
        }
    }
    panic!("missing slot {wanted}")
}
fn check_hashes(signed: &[u8], info: &[u8], resources: &[u8]) {
    let sig = signature(signed);
    assert_eq!(get32(sig, 0), 0xfade0cc0);
    assert_eq!(get32(sig, 4), sig.len());
    let code_len = signed.len() - sig.len();
    for (number, size) in [(0, 20), (0x1000, 32)] {
        let cd = slot(sig, number);
        let off = get32(cd, 16);
        assert_eq!(get32(cd, 32), code_len);
        let hash = |b: &[u8]| {
            if size == 20 {
                sha1(b).to_vec()
            } else {
                sha256(b).to_vec()
            }
        };
        assert_eq!(&cd[off - size..off], hash(info));
        assert_eq!(&cd[off - 3 * size..off - 2 * size], hash(resources));
        for (i, page) in signed[..code_len].chunks(4096).enumerate() {
            assert_eq!(&cd[off + i * size..off + (i + 1) * size], hash(page));
        }
        for s in [2, 5, 7] {
            assert_eq!(
                &cd[off - s * size..off - (s - 1) * size],
                hash(slot(sig, s))
            );
        }
    }
}
#[test]
fn thin_sign_and_resign_both_widths() {
    for wide in [false, true] {
        let identity = identity();
        let e = Dictionary::from_iter([("get-task-allow", Value::Boolean(true))]);
        let (signed, _) = sign_macho(
            &thin(wide),
            "com.test.app",
            &identity,
            Some(b"info"),
            Some(b"resources"),
            Some(&e),
        )
        .unwrap();
        check_hashes(&signed, b"info", b"resources");
        let (resigned, _) = sign_macho(
            &signed,
            "com.test.app",
            &identity,
            Some(b"info"),
            Some(b"resources"),
            Some(&e),
        )
        .unwrap();
        assert_eq!(signed, resigned);
    }
}
#[test]
fn fat_signing_and_malformed_inputs() {
    let a = thin(false);
    let b = thin(true);
    let mut fat = vec![0; 4096];
    fat[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    fat[4..8].copy_from_slice(&2u32.to_be_bytes());
    for (p, cpu, off, size) in [
        (8, 12u32, 4096u32, a.len()),
        (28, 0x100000c, 12288, b.len()),
    ] {
        for (o, v) in [(0, cpu), (4, 0), (8, off), (12, size as u32), (16, 12)] {
            fat[p + o..p + o + 4].copy_from_slice(&v.to_be_bytes());
        }
    }
    fat.extend(a);
    fat.extend(b);
    let (signed, _) = sign_macho(&fat, "com.test", &identity(), None, None, None).unwrap();
    for p in [8, 28] {
        let off = get32(&signed, p + 8);
        let size = get32(&signed, p + 12);
        assert_eq!(get32(signature(&signed[off..off + size]), 0), 0xfade0cc0);
    }
    fat[36..40].copy_from_slice(&4096u32.to_be_bytes());
    assert!(sign_macho(&fat, "com.test", &identity(), None, None, None).is_err());
    for len in 0..512 {
        let _ = macho::prepare(&thin(true)[..len]);
    }
    let mut bad = thin(true);
    put32(&mut bad, 36, 0xfffffff8);
    assert!(macho::prepare(&bad).is_err());
    let mut encrypted = thin(true);
    let cmdend = 32 + u32::from_le_bytes(encrypted[20..24].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(encrypted[16..20].try_into().unwrap());
    put32(&mut encrypted, 16, count + 1);
    put32(&mut encrypted, 20, (cmdend - 32 + 24) as u32);
    put32(&mut encrypted, cmdend, 0x2c);
    put32(&mut encrypted, cmdend + 4, 24);
    put32(&mut encrypted, cmdend + 16, 1);
    assert!(
        macho::prepare(&encrypted)
            .unwrap_err()
            .contains("encrypted")
    );
}
fn app(root: &Path, id: &str) {
    fs::create_dir_all(root).unwrap();
    let d = Dictionary::from_iter([
        ("CFBundleIdentifier", Value::from(id)),
        ("CFBundleExecutable", Value::from("Executable")),
    ]);
    fs::write(root.join("Info.plist"), Value::Dictionary(d).to_xml()).unwrap();
    fs::write(root.join("Executable"), thin(true)).unwrap();
}
fn profile(id: &str, identity: &SigningIdentity) -> Vec<u8> {
    let mut ents = Dictionary::new();
    ents.insert("application-identifier", format!("TEAM.{id}"));
    ents.insert("com.apple.developer.team-identifier", "TEAM");
    ents.insert("get-task-allow", true);
    let p = Value::Dictionary(Dictionary::from_iter([
        ("Entitlements", Value::Dictionary(ents)),
        (
            "DeveloperCertificates",
            Value::Array(vec![Value::Data(identity.certificates[0].clone())]),
        ),
    ]))
    .to_xml();
    // Minimal SignedData container sufficient for profile content extraction.
    der::sequence([
        der::oid("1.2.840.113549.1.7.2"),
        der::explicit(
            0,
            &der::sequence([
                der::integer(1),
                der::set_of(Vec::<Vec<u8>>::new()),
                der::sequence([
                    der::oid("1.2.840.113549.1.7.1"),
                    der::explicit(0, &der::octet_string(&p)),
                ]),
            ]),
        ),
    ])
}
#[test]
fn bundle_profiles_frameworks_resources_and_parallelism() {
    for threads in [1, 3] {
        let temp = Temp::new();
        let root = temp.0.join("Test.app");
        app(&root, "com.test");
        let extension = root.join("PlugIns/Widget.appex");
        app(&extension, "com.test.widget");
        app(&root.join("Frameworks/Library.framework"), "com.library");
        fs::write(root.join("Frameworks/a.dylib"), thin(true)).unwrap();
        fs::write(root.join("Frameworks/b.dylib"), thin(false)).unwrap();
        fs::write(root.join("asset.txt"), b"asset").unwrap();
        let identity = identity();
        let profiles = BTreeMap::from([
            ("com.test".into(), profile("com.test", &identity)),
            (
                "com.test.widget".into(),
                profile("com.test.widget", &identity),
            ),
        ]);
        let bundle = AppBundle::load(&root).unwrap();
        let missing = sign_bundle(&bundle, &identity, &BTreeMap::new(), threads).unwrap_err();
        assert_eq!(missing.code, ErrorCode::SigningFailed);
        assert!(missing.message.contains("Widget.appex"));
        assert!(!root.join("embedded.mobileprovision").exists());
        sign_bundle(&bundle, &identity, &profiles, threads).unwrap();
        for (path, id) in [(&root, "com.test"), (&extension, "com.test.widget")] {
            assert_eq!(
                fs::read(path.join("embedded.mobileprovision")).unwrap(),
                profiles[id]
            );
            let signed = fs::read(path.join("Executable")).unwrap();
            let res = fs::read(path.join("_CodeSignature/CodeResources")).unwrap();
            let info = fs::read(path.join("Info.plist")).unwrap();
            check_hashes(&signed, &info, &res);
            let ents = slot(signature(&signed), 5);
            let e = plist::from_bytes(&ents[8..]).unwrap();
            assert_eq!(
                e.get("application-identifier").and_then(Value::as_str),
                Some(format!("TEAM.{id}").as_str())
            );
        }
        let r = plist::from_bytes(&fs::read(root.join("_CodeSignature/CodeResources")).unwrap())
            .unwrap();
        let files = r.get("files2").unwrap();
        assert!(
            files
                .get("Frameworks/Library.framework")
                .unwrap()
                .get("cdhash")
                .is_some()
        );
        assert!(
            files
                .get("PlugIns/Widget.appex")
                .unwrap()
                .get("requirement")
                .is_some()
        );
        assert!(files.get("asset.txt").unwrap().get("hash2").is_some());
        assert!(
            !root
                .join("Frameworks/Library.framework/embedded.mobileprovision")
                .exists()
        );
        sign_bundle(&bundle, &identity, &profiles, threads).unwrap();
    }
}
#[test]
fn openssl_verifies_detached_cms() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipped: openssl is unavailable");
        return;
    }
    let t = Temp::new();
    let (signed, _) = sign_macho(&thin(true), "com.test", &identity(), None, None, None).unwrap();
    let sig = signature(&signed);
    fs::write(t.0.join("directory"), slot(sig, 0)).unwrap();
    fs::write(t.0.join("signature.der"), &slot(sig, 0x10000)[8..]).unwrap();
    let result = Command::new("openssl")
        .current_dir(&t.0)
        .args([
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-in",
            "signature.der",
            "-content",
            "directory",
            "-binary",
            "-noverify",
            "-out",
            "verified",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    fs::write(t.0.join("directory"), b"tampered").unwrap();
    assert!(
        !Command::new("openssl")
            .current_dir(&t.0)
            .args([
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                "signature.der",
                "-content",
                "directory",
                "-binary",
                "-noverify",
                "-out",
                "bad"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
}

/// Explicit integration check against a separately distributed implementation.
#[test]
#[ignore = "set RCODESIGN to an independent rcodesign executable"]
fn independent_rcodesign_verification() {
    let tool = std::env::var_os("RCODESIGN").expect("set RCODESIGN");
    let t = Temp::new();
    let path = t.0.join("signed-macho");
    let e = Dictionary::from_iter([("get-task-allow", Value::Boolean(true))]);
    for wide in [false, true] {
        let (signed, _) =
            sign_macho(&thin(wide), "com.test", &identity(), None, None, Some(&e)).unwrap();
        fs::write(&path, &signed).unwrap();
        for args in [
            vec!["verify"],
            vec!["extract", "requirements"],
            vec!["extract", "cms-info"],
        ] {
            let result = Command::new(&tool).args(args).arg(&path).output().unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let mut tampered = signed;
        tampered[512] ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(
            !Command::new(&tool)
                .arg("verify")
                .arg(&path)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}

#[test]
fn profile_ber_from_openssl() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipped: openssl is unavailable");
        return;
    }
    let t = Temp::new();
    let identity = identity();
    let value = entitlements::profile_plist(&profile("com.test", &identity)).unwrap();
    fs::write(t.0.join("profile.plist"), value.to_xml()).unwrap();
    fs::write(
        t.0.join("cert.pem"),
        include_str!("testdata/certificate.pem"),
    )
    .unwrap();
    fs::write(
        t.0.join("key.pem"),
        include_str!("../crypto/testdata/openssl_key.pem"),
    )
    .unwrap();
    let output = Command::new("openssl")
        .current_dir(&t.0)
        .args([
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-stream",
            "-in",
            "profile.plist",
            "-signer",
            "cert.pem",
            "-inkey",
            "key.pem",
            "-outform",
            "DER",
            "-out",
            "profile.der",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        entitlements::profile_plist(&fs::read(t.0.join("profile.der")).unwrap()).unwrap(),
        value
    );
    assert!(entitlements::profile_plist(b"broken").is_err());
}

#[test]
fn rejects_wrong_identity_and_profile_certificate() {
    let t = Temp::new();
    let root = t.0.join("Test.app");
    app(&root, "com.test");
    let b = AppBundle::load(&root).unwrap();
    let mut identity = identity();
    let raw = profile("com.test", &identity);
    let mut p = entitlements::profile_plist(&raw).unwrap();
    p.as_dict_mut().unwrap().insert(
        "DeveloperCertificates",
        Value::Array(vec![Value::Data(vec![1, 2, 3])]),
    );
    // An unauthorized profile must be rejected before any profile is embedded.
    let wrapped = der::sequence([
        der::oid("1.2.840.113549.1.7.2"),
        der::explicit(
            0,
            &der::sequence([
                der::integer(1),
                der::set_of(Vec::<Vec<u8>>::new()),
                der::sequence([
                    der::oid("1.2.840.113549.1.7.1"),
                    der::explicit(0, &der::octet_string(&p.to_xml())),
                ]),
            ]),
        ),
    ]);
    let e = sign_bundle(
        &b,
        &identity,
        &BTreeMap::from([("com.test".into(), wrapped)]),
        1,
    )
    .unwrap_err();
    assert!(e.message.contains("not authorized"));
    assert!(!root.join("embedded.mobileprovision").exists());
    identity.private_key.n += 1u32;
    assert!(
        sign_bundle(
            &b,
            &identity,
            &BTreeMap::from([("com.test".into(), raw)]),
            1
        )
        .unwrap_err()
        .message
        .contains("does not match")
    );
}

#[cfg(unix)]
#[test]
fn symlink_seals_and_output_safety() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    let root = t.0.join("Test.app");
    app(&root, "com.test");
    fs::write(root.join("asset"), b"original").unwrap();
    symlink("asset", root.join("link")).unwrap();
    let resources = code_resources::build(&root, "Executable", &BTreeMap::new()).unwrap();
    let r = plist::from_bytes(&resources).unwrap();
    assert_eq!(
        r.get("files2")
            .unwrap()
            .get("link")
            .unwrap()
            .get("symlink")
            .and_then(Value::as_str),
        Some("asset")
    );
    symlink("asset", root.join("embedded.mobileprovision")).unwrap();
    let identity = identity();
    let b = AppBundle::load(&root).unwrap();
    assert!(
        sign_bundle(
            &b,
            &identity,
            &BTreeMap::from([("com.test".into(), profile("com.test", &identity))]),
            1
        )
        .unwrap_err()
        .message
        .contains("symlink")
    );
    assert_eq!(fs::read(root.join("asset")).unwrap(), b"original");
}

#[test]
fn fat_magic_alone_is_not_code() {
    // Java class file: CAFEBABE, minor 0, major 52.
    let mut class = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34];
    class.extend([0u8; 64]);
    assert!(macho::is_fat_magic(&class));
    assert!(!macho::looks_like_fat_macho(&class));
    // A small table whose slice is not a thin Mach-O is also rejected.
    let mut fake = vec![0; 64];
    fake[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    fake[4..8].copy_from_slice(&1u32.to_be_bytes());
    fake[16..20].copy_from_slice(&32u32.to_be_bytes()); // offset
    fake[20..24].copy_from_slice(&16u32.to_be_bytes()); // size
    assert!(!macho::looks_like_fat_macho(&fake));

    // A real universal binary is still recognized.
    let a = thin(true);
    let mut fat = vec![0; 4096];
    fat[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    fat[4..8].copy_from_slice(&1u32.to_be_bytes());
    for (o, v) in [
        (0, 0x100000cu32),
        (4, 0),
        (8, 4096),
        (12, a.len() as u32),
        (16, 12),
    ] {
        fat[8 + o..12 + o].copy_from_slice(&v.to_be_bytes());
    }
    fat.extend(&a);
    assert!(macho::looks_like_fat_macho(&fat));

    // In a bundle, the class file is sealed as a resource and signing succeeds.
    let temp = Temp::new();
    let root = temp.0.join("Java.app");
    app(&root, "com.test");
    fs::write(root.join("Helper.class"), &class).unwrap();
    fs::write(root.join("Universal"), &fat).unwrap();
    let identity = identity();
    let profiles = BTreeMap::from([("com.test".into(), profile("com.test", &identity))]);
    sign_bundle(&AppBundle::load(&root).unwrap(), &identity, &profiles, 1).unwrap();
    assert_eq!(fs::read(root.join("Helper.class")).unwrap(), class);
    let r =
        plist::from_bytes(&fs::read(root.join("_CodeSignature/CodeResources")).unwrap()).unwrap();
    let files = r.get("files2").unwrap();
    assert!(files.get("Helper.class").unwrap().get("hash2").is_some());
    assert!(files.get("Universal").unwrap().get("cdhash").is_some());
}

#[test]
fn identity_with_apple_chain() {
    let base = identity();
    let leaf = base.certificates[0].clone();
    let id =
        SigningIdentity::with_apple_chain(leaf.clone(), base.private_key.clone(), "TEAM".into());
    assert_eq!(id.certificates.first(), Some(&leaf));
    assert_eq!(
        id.certificates.last().map(Vec::as_slice),
        Some(super::apple_certs::ROOT_CA)
    );
    // The Apple certificates end up in the CMS certificate set.
    let (signed, _) = sign_macho(&thin(true), "com.test", &id, None, None, None).unwrap();
    let cms = slot(signature(&signed), 0x10000);
    let root_in_cms = cms
        .windows(super::apple_certs::ROOT_CA.len())
        .any(|w| w == super::apple_certs::ROOT_CA);
    assert!(root_in_cms);
}
