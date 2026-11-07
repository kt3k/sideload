//! IPA extraction and repacking (SPEC Sections 11.1, 11.3, 14.3).
//!
//! Extraction rejects member names with `..`, absolute paths or drive
//! prefixes, and symbolic links whose target leaves the extraction root.

use std::fs;
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};

use crate::formats::zip::{ZipReader, ZipWriter};
use crate::{Error, ErrorCode, Result};

/// Upper bound on the total extracted size (zip-bomb guard).
pub const MAX_TOTAL_BYTES: u64 = 16 << 30;

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::IpaInvalid, msg)
}

fn io_err(path: &Path, e: std::io::Error) -> Error {
    Error::new(ErrorCode::IpaInvalid, format!("`{}`: {e}", path.display()))
}

/// True if `target`, resolved relative to the directory of `link` (both
/// relative to the extraction root), stays inside the root.
fn symlink_stays_inside(link: &Path, target: &str) -> bool {
    if target.is_empty() || target.starts_with('/') || target.contains('\\') {
        return false;
    }
    let mut depth: i64 = link.components().count() as i64 - 1;
    for part in Path::new(target).components() {
        match part {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Extracts `ipa` into `dest` and returns the path of the single
/// `Payload/<name>.app` directory.
pub fn extract(ipa: &Path, dest: &Path) -> Result<PathBuf> {
    let file = fs::File::open(ipa).map_err(|e| io_err(ipa, e))?;
    extract_from(file, dest)
}

pub fn extract_from<R: Read + Seek>(reader: R, dest: &Path) -> Result<PathBuf> {
    let mut zip = ZipReader::new(reader).map_err(|e| invalid(e.to_string()))?;
    let total: u64 = zip.entries().iter().map(|e| e.uncompressed_size).sum();
    if total > MAX_TOTAL_BYTES {
        return Err(invalid("the IPA expands to more than 16 GiB"));
    }

    let mut apps = std::collections::BTreeSet::new();
    for index in 0..zip.entries().len() {
        let entry = zip.entries()[index].clone();
        let rel = entry
            .safe_path()
            .ok_or_else(|| invalid(format!("unsafe path in IPA: `{}`", entry.name)))?;
        let mut comps = rel.components();
        if let (Some(Component::Normal(first)), Some(Component::Normal(second))) =
            (comps.next(), comps.next())
        {
            let second = second.to_string_lossy();
            if first == "Payload" && second.ends_with(".app") {
                apps.insert(second.into_owned());
            }
        }
        let out = dest.join(&rel);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(|e| io_err(&out, e))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        let data = zip.read(index).map_err(|e| invalid(e.to_string()))?;
        if entry.is_symlink() {
            let target = String::from_utf8(data)
                .map_err(|_| invalid(format!("non-UTF-8 symlink `{}`", entry.name)))?;
            if !symlink_stays_inside(&rel, &target) {
                return Err(invalid(format!(
                    "symlink `{}` points outside the IPA: `{target}`",
                    entry.name
                )));
            }
            make_symlink(&target, &out)?;
            continue;
        }
        fs::write(&out, &data).map_err(|e| io_err(&out, e))?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            // Keep rwx bits only; never setuid/setgid/sticky.
            let mode = (mode & 0o777) | 0o600;
            fs::set_permissions(&out, fs::Permissions::from_mode(mode))
                .map_err(|e| io_err(&out, e))?;
        }
    }

    match apps.len() {
        1 => Ok(dest
            .join("Payload")
            .join(apps.into_iter().next().unwrap_or_default())),
        0 => Err(invalid("the IPA contains no Payload/<name>.app")),
        n => Err(invalid(format!(
            "the IPA contains {n} apps in Payload/; expected exactly one"
        ))),
    }
}

#[cfg(unix)]
fn make_symlink(target: &str, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link).map_err(|e| io_err(link, e))
}

#[cfg(not(unix))]
fn make_symlink(_target: &str, link: &Path) -> Result<()> {
    Err(invalid(format!(
        "`{}` is a symbolic link, which is not supported on this platform",
        link.display()
    )))
}

/// Writes `root/Payload/...` (the directory `extract` wrote into) as an IPA
/// at `out` (SPEC Section 11.3): written to a temporary file first, then
/// renamed into place.
pub fn repack(root: &Path, out: &Path) -> Result<()> {
    let fail = |e: String| Error::new(ErrorCode::OutputWriteFailed, e);
    let tmp = out.with_extension("ipa.partial");
    let result = (|| -> Result<()> {
        let file = fs::File::create(&tmp).map_err(|e| fail(format!("`{}`: {e}", tmp.display())))?;
        let mut zip = ZipWriter::new(std::io::BufWriter::new(file));
        add_tree(&mut zip, root, Path::new("Payload")).map_err(|e| fail(e.message))?;
        zip.finish().map_err(|e| fail(e.to_string()))?;
        fs::rename(&tmp, out).map_err(|e| fail(format!("`{}`: {e}", out.display())))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn zip_name(rel: &Path) -> String {
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn add_tree<W: std::io::Write>(zip: &mut ZipWriter<W>, root: &Path, rel: &Path) -> Result<()> {
    let path = root.join(rel);
    let meta = fs::symlink_metadata(&path).map_err(|e| io_err(&path, e))?;
    let name = zip_name(rel);
    let ioe =
        |e: crate::formats::FormatError| Error::new(ErrorCode::OutputWriteFailed, e.to_string());
    if meta.file_type().is_symlink() {
        let target = fs::read_link(&path).map_err(|e| io_err(&path, e))?;
        zip.add_symlink(&name, &target.to_string_lossy())
            .map_err(ioe)
    } else if meta.is_dir() {
        zip.add_directory(&name, mode_of(&meta, 0o755))
            .map_err(ioe)?;
        let mut children: Vec<_> = fs::read_dir(&path)
            .map_err(|e| io_err(&path, e))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<_>>()
            .map_err(|e| io_err(&path, e))?;
        children.sort();
        for child in children {
            add_tree(zip, root, &rel.join(child))?;
        }
        Ok(())
    } else {
        let data = fs::read(&path).map_err(|e| io_err(&path, e))?;
        zip.add_file(&name, &data, mode_of(&meta, 0o644), true)
            .map_err(ioe)
    }
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata, _default: u32) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata, default: u32) -> u32 {
    default
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    pub(crate) fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sideload-ipa-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ipa(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Vec::new());
        for (name, data) in entries {
            if name.ends_with('/') {
                w.add_directory(name, 0o755).unwrap();
            } else {
                w.add_file(name, data, 0o755, true).unwrap();
            }
        }
        w.finish().unwrap()
    }

    #[test]
    fn symlink_containment() {
        let link = Path::new("Payload/A.app/Frameworks/F.framework/Current");
        assert!(symlink_stays_inside(link, "Versions/A"));
        assert!(symlink_stays_inside(link, "../../Info.plist"));
        assert!(symlink_stays_inside(link, "../../../../x"));
        assert!(!symlink_stays_inside(link, "../../../../../x"));
        assert!(!symlink_stays_inside(link, "/etc/passwd"));
        assert!(!symlink_stays_inside(link, ""));
    }

    #[test]
    fn extracts_single_app() {
        let dir = temp_dir("extract");
        let data = ipa(&[
            ("Payload/", b""),
            ("Payload/A.app/Info.plist", b"<plist/>"),
            ("Payload/A.app/A", b"bin"),
        ]);
        let app = extract_from(Cursor::new(data), &dir).unwrap();
        assert_eq!(app, dir.join("Payload/A.app"));
        assert_eq!(fs::read(app.join("A")).unwrap(), b"bin");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_bad_layouts_and_paths() {
        let dir = temp_dir("reject");
        let none = ipa(&[("Other/x", b"")]);
        assert_eq!(
            extract_from(Cursor::new(none), &dir).unwrap_err().code,
            ErrorCode::IpaInvalid
        );
        let two = ipa(&[("Payload/A.app/x", b""), ("Payload/B.app/x", b"")]);
        assert!(
            extract_from(Cursor::new(two), &dir)
                .unwrap_err()
                .message
                .contains("2 apps")
        );
        let evil = ipa(&[("Payload/A.app/../../evil", b"")]);
        assert!(
            extract_from(Cursor::new(evil), &dir)
                .unwrap_err()
                .message
                .contains("unsafe path")
        );
        assert!(!dir.parent().unwrap().join("evil").exists());
        assert!(extract_from(Cursor::new(b"not a zip".to_vec()), &dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_escaping_symlinks() {
        let dir = temp_dir("symlink");
        let mut w = ZipWriter::new(Vec::new());
        w.add_file("Payload/A.app/A", b"x", 0o755, false).unwrap();
        w.add_symlink("Payload/A.app/link", "../../../outside")
            .unwrap();
        let data = w.finish().unwrap();
        assert!(
            extract_from(Cursor::new(data), &dir)
                .unwrap_err()
                .message
                .contains("points outside")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn repack_roundtrip() {
        let dir = temp_dir("repack");
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        let data = ipa(&[
            ("Payload/A.app/Info.plist", b"<plist/>"),
            ("Payload/A.app/sub/f", b"data"),
        ]);
        extract_from(Cursor::new(data), &src).unwrap();
        let out = dir.join("out.ipa");
        repack(&src, &out).unwrap();
        assert!(!dir.join("out.ipa.partial").exists());
        let again = dir.join("again");
        fs::create_dir_all(&again).unwrap();
        let app = extract(&out, &again).unwrap();
        assert_eq!(fs::read(app.join("sub/f")).unwrap(), b"data");
        fs::remove_dir_all(dir).unwrap();
    }
}
