//! ZIP container (PKWARE APPNOTE): reading with ZIP64 support, writing with
//! ZIP64 when needed. Methods: stored (0) and deflate (8, via `miniz_oxide`).
//! Encryption and multi-disk archives are not supported.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use super::{FormatError, FormatResult};

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_EOCD64_LOCATOR: u32 = 0x0706_4b50;
const ZIP64_EXTRA: u16 = 0x0001;
const FLAG_ENCRYPTED: u16 = 1;
const FLAG_UTF8: u16 = 1 << 11;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

fn err(msg: impl Into<String>) -> FormatError {
    FormatError::new(format!("zip: {}", msg.into()))
}

// ---------------------------------------------------------------- CRC-32

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

pub fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |c, &b| {
        CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8)
    })
}

// ---------------------------------------------------------------- little-endian helpers

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

// ---------------------------------------------------------------- reading

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Raw name as stored (`/`-separated). Directories end with `/`.
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub version_made_by: u16,
    pub external_attributes: u32,
    local_header_offset: u64,
}

impl Entry {
    /// Unix mode bits, when the archive was made on Unix.
    pub fn unix_mode(&self) -> Option<u32> {
        (self.version_made_by >> 8 == 3).then_some(self.external_attributes >> 16)
    }

    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.unix_mode().is_some_and(|m| m & S_IFMT == S_IFDIR)
    }

    pub fn is_symlink(&self) -> bool {
        self.unix_mode().is_some_and(|m| m & S_IFMT == S_IFLNK)
    }

    /// The name as a relative path, or `None` if it is absolute, contains
    /// `..`, a drive prefix or a backslash (SPEC Section 14.3).
    pub fn safe_path(&self) -> Option<PathBuf> {
        safe_relative_path(&self.name)
    }
}

/// Validates an archive member name and converts it to a relative path.
pub fn safe_relative_path(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('\\') || name.contains('\0') {
        return None;
    }
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    let mut out = PathBuf::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." {
            if part.is_empty() && out.as_os_str().is_empty() && name.starts_with('/') {
                return None; // absolute
            }
            continue;
        }
        // A Windows drive prefix is a normal component on Unix; reject it
        // everywhere so behavior does not depend on the host.
        let b = part.as_bytes();
        if out.as_os_str().is_empty() && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
        {
            return None;
        }
        let mut comps = Path::new(part).components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(p)), None) => out.push(p),
            _ => return None, // "..", prefixes like "C:", roots
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

pub struct ZipReader<R> {
    inner: R,
    entries: Vec<Entry>,
    len: u64,
}

impl<R: Read + Seek> ZipReader<R> {
    pub fn new(mut inner: R) -> FormatResult<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        let tail_len = len.min(22 + 0xFFFF);
        inner.seek(SeekFrom::Start(len - tail_len))?;
        let mut tail = vec![0; tail_len as usize];
        inner.read_exact(&mut tail)?;

        let eocd = (0..tail.len().saturating_sub(21))
            .rev()
            .find(|&i| u32_at(&tail, i) == SIG_EOCD)
            .ok_or_else(|| err("end of central directory not found"))?;
        let e = &tail[eocd..];
        if u16_at(e, 4) != 0 || u16_at(e, 6) != 0 {
            return Err(err("multi-disk archives are not supported"));
        }
        let mut count = u64::from(u16_at(e, 10));
        let mut cd_size = u64::from(u32_at(e, 12));
        let mut cd_offset = u64::from(u32_at(e, 16));

        if count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
            let eocd_abs = len - tail_len + eocd as u64;
            let loc_pos = eocd_abs
                .checked_sub(20)
                .ok_or_else(|| err("missing ZIP64 locator"))?;
            let mut loc = [0u8; 20];
            inner.seek(SeekFrom::Start(loc_pos))?;
            inner.read_exact(&mut loc)?;
            if u32_at(&loc, 0) != SIG_EOCD64_LOCATOR {
                return Err(err("missing ZIP64 locator"));
            }
            let mut rec = [0u8; 56];
            inner.seek(SeekFrom::Start(u64_at(&loc, 8)))?;
            inner.read_exact(&mut rec)?;
            if u32_at(&rec, 0) != SIG_EOCD64 {
                return Err(err("invalid ZIP64 end of central directory"));
            }
            count = u64_at(&rec, 32);
            cd_size = u64_at(&rec, 40);
            cd_offset = u64_at(&rec, 48);
        }

        if cd_offset.checked_add(cd_size).is_none_or(|end| end > len) {
            return Err(err("central directory out of range"));
        }
        let mut cd = vec![0; cd_size as usize];
        inner.seek(SeekFrom::Start(cd_offset))?;
        inner.read_exact(&mut cd)?;

        let mut entries = Vec::new();
        let mut pos = 0usize;
        for _ in 0..count {
            if pos + 46 > cd.len() || u32_at(&cd, pos) != SIG_CENTRAL {
                return Err(err("invalid central directory entry"));
            }
            let h = &cd[pos..];
            let flags = u16_at(h, 8);
            if flags & FLAG_ENCRYPTED != 0 {
                return Err(err("encrypted entries are not supported"));
            }
            let name_len = usize::from(u16_at(h, 28));
            let extra_len = usize::from(u16_at(h, 30));
            let comment_len = usize::from(u16_at(h, 32));
            let total = 46 + name_len + extra_len + comment_len;
            if pos + total > cd.len() {
                return Err(err("truncated central directory entry"));
            }
            let name_bytes = &h[46..46 + name_len];
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|_| err("entry name is not valid UTF-8"))?;
            let mut entry = Entry {
                name,
                method: u16_at(h, 10),
                crc32: u32_at(h, 16),
                compressed_size: u64::from(u32_at(h, 20)),
                uncompressed_size: u64::from(u32_at(h, 24)),
                version_made_by: u16_at(h, 4),
                external_attributes: u32_at(h, 38),
                local_header_offset: u64::from(u32_at(h, 42)),
            };
            apply_zip64_extra(&mut entry, &h[46 + name_len..46 + name_len + extra_len])?;
            entries.push(entry);
            pos += total;
        }
        Ok(ZipReader {
            inner,
            entries,
            len,
        })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Reads and decompresses entry `index`, verifying size and CRC-32.
    pub fn read(&mut self, index: usize) -> FormatResult<Vec<u8>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| err("entry index out of range"))?
            .clone();
        let mut local = [0u8; 30];
        self.inner
            .seek(SeekFrom::Start(entry.local_header_offset))?;
        self.inner.read_exact(&mut local)?;
        if u32_at(&local, 0) != SIG_LOCAL {
            return Err(err(format!("invalid local header for `{}`", entry.name)));
        }
        let skip = u64::from(u16_at(&local, 26)) + u64::from(u16_at(&local, 28));
        let data_start = self.inner.seek(SeekFrom::Current(skip as i64))?;
        // Check declared sizes against the file before allocating.
        if data_start
            .checked_add(entry.compressed_size)
            .is_none_or(|end| end > self.len)
        {
            return Err(err(format!(
                "`{}` extends past the end of the archive",
                entry.name
            )));
        }

        let csize = usize::try_from(entry.compressed_size).map_err(|_| err("entry too large"))?;
        let usize_ =
            usize::try_from(entry.uncompressed_size).map_err(|_| err("entry too large"))?;
        let mut raw = vec![0; csize];
        self.inner.read_exact(&mut raw)?;
        let data = match entry.method {
            METHOD_STORED => raw,
            METHOD_DEFLATE => miniz_oxide::inflate::decompress_to_vec_with_limit(&raw, usize_)
                .map_err(|e| err(format!("cannot inflate `{}`: {e:?}", entry.name)))?,
            m => {
                return Err(err(format!(
                    "unsupported compression method {m} for `{}`",
                    entry.name
                )));
            }
        };
        if data.len() != usize_ {
            return Err(err(format!("size mismatch for `{}`", entry.name)));
        }
        if crc32(&data) != entry.crc32 {
            return Err(err(format!("CRC mismatch for `{}`", entry.name)));
        }
        Ok(data)
    }
}

fn apply_zip64_extra(entry: &mut Entry, mut extra: &[u8]) -> FormatResult<()> {
    while extra.len() >= 4 {
        let id = u16_at(extra, 0);
        let len = usize::from(u16_at(extra, 2));
        let body = extra
            .get(4..4 + len)
            .ok_or_else(|| err("truncated extra field"))?;
        if id == ZIP64_EXTRA {
            let mut fields = body.chunks_exact(8).map(|c| u64_at(c, 0));
            let mut next = || {
                fields
                    .next()
                    .ok_or_else(|| err("truncated ZIP64 extra field"))
            };
            if entry.uncompressed_size == 0xFFFF_FFFF {
                entry.uncompressed_size = next()?;
            }
            if entry.compressed_size == 0xFFFF_FFFF {
                entry.compressed_size = next()?;
            }
            if entry.local_header_offset == 0xFFFF_FFFF {
                entry.local_header_offset = next()?;
            }
        }
        extra = &extra[4 + len..];
    }
    Ok(())
}

// ---------------------------------------------------------------- writing

struct CentralRecord {
    name: String,
    method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    external_attributes: u32,
    offset: u64,
}

/// Streams entries to `W`. Each entry is compressed in memory first, so the
/// local header carries the final sizes (no data descriptors).
pub struct ZipWriter<W> {
    inner: W,
    offset: u64,
    central: Vec<CentralRecord>,
}

/// DOS date for 1980-01-01 00:00, for reproducible archives.
const DOS_DATE: u16 = (1 << 5) | 1;
const DOS_TIME: u16 = 0;
/// "Made by" Unix, spec version 4.5.
const VERSION_MADE_BY: u16 = (3 << 8) | 45;

impl<W: Write> ZipWriter<W> {
    pub fn new(inner: W) -> Self {
        ZipWriter {
            inner,
            offset: 0,
            central: Vec::new(),
        }
    }

    pub fn add_file(
        &mut self,
        name: &str,
        data: &[u8],
        mode: u32,
        compress: bool,
    ) -> FormatResult<()> {
        let (method, payload) = if compress && !data.is_empty() {
            let deflated = miniz_oxide::deflate::compress_to_vec(data, 6);
            if deflated.len() < data.len() {
                (METHOD_DEFLATE, deflated)
            } else {
                (METHOD_STORED, data.to_vec())
            }
        } else {
            (METHOD_STORED, data.to_vec())
        };
        self.add_raw(
            name,
            method,
            crc32(data),
            data.len() as u64,
            &payload,
            S_IFREG | (mode & 0o7777),
        )
    }

    pub fn add_directory(&mut self, name: &str, mode: u32) -> FormatResult<()> {
        let name = if name.ends_with('/') {
            name.to_owned()
        } else {
            format!("{name}/")
        };
        // MS-DOS directory attribute in the low byte.
        self.add_raw(&name, METHOD_STORED, 0, 0, &[], S_IFDIR | (mode & 0o7777))
            .map(|_| {
                self.central
                    .last_mut()
                    .map(|r| r.external_attributes |= 0x10)
                    .unwrap_or(())
            })
    }

    pub fn add_symlink(&mut self, name: &str, target: &str) -> FormatResult<()> {
        let t = target.as_bytes();
        self.add_raw(
            name,
            METHOD_STORED,
            crc32(t),
            t.len() as u64,
            t,
            S_IFLNK | 0o777,
        )
    }

    fn add_raw(
        &mut self,
        name: &str,
        method: u16,
        crc: u32,
        usize_: u64,
        payload: &[u8],
        unix_mode: u32,
    ) -> FormatResult<()> {
        if name.len() > 0xFFFF {
            return Err(err("entry name too long"));
        }
        let csize = payload.len() as u64;
        let zip64 = usize_ >= 0xFFFF_FFFF || csize >= 0xFFFF_FFFF;

        let mut h = Vec::with_capacity(30 + name.len() + 20);
        h.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        h.extend_from_slice(&(if zip64 { 45u16 } else { 20u16 }).to_le_bytes());
        h.extend_from_slice(&FLAG_UTF8.to_le_bytes());
        h.extend_from_slice(&method.to_le_bytes());
        h.extend_from_slice(&DOS_TIME.to_le_bytes());
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        let (cs32, us32) = if zip64 {
            (0xFFFF_FFFF, 0xFFFF_FFFF)
        } else {
            (csize as u32, usize_ as u32)
        };
        h.extend_from_slice(&cs32.to_le_bytes());
        h.extend_from_slice(&us32.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(if zip64 { 20u16 } else { 0u16 }).to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        if zip64 {
            h.extend_from_slice(&ZIP64_EXTRA.to_le_bytes());
            h.extend_from_slice(&16u16.to_le_bytes());
            h.extend_from_slice(&usize_.to_le_bytes());
            h.extend_from_slice(&csize.to_le_bytes());
        }
        self.inner.write_all(&h)?;
        self.inner.write_all(payload)?;

        self.central.push(CentralRecord {
            name: name.to_owned(),
            method,
            crc32: crc,
            compressed_size: csize,
            uncompressed_size: usize_,
            external_attributes: unix_mode << 16,
            offset: self.offset,
        });
        self.offset += (h.len() + payload.len()) as u64;
        Ok(())
    }

    /// Writes the central directory and returns the inner writer.
    pub fn finish(mut self) -> FormatResult<W> {
        let cd_offset = self.offset;
        let mut cd = Vec::new();
        for r in &self.central {
            let mut extra = Vec::new();
            if r.uncompressed_size >= 0xFFFF_FFFF {
                extra.extend_from_slice(&r.uncompressed_size.to_le_bytes());
            }
            if r.compressed_size >= 0xFFFF_FFFF {
                extra.extend_from_slice(&r.compressed_size.to_le_bytes());
            }
            if r.offset >= 0xFFFF_FFFF {
                extra.extend_from_slice(&r.offset.to_le_bytes());
            }
            let clamp = |v: u64| {
                if v >= 0xFFFF_FFFF {
                    0xFFFF_FFFFu32
                } else {
                    v as u32
                }
            };
            cd.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
            cd.extend_from_slice(&VERSION_MADE_BY.to_le_bytes());
            cd.extend_from_slice(&(if extra.is_empty() { 20u16 } else { 45u16 }).to_le_bytes());
            cd.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            cd.extend_from_slice(&r.method.to_le_bytes());
            cd.extend_from_slice(&DOS_TIME.to_le_bytes());
            cd.extend_from_slice(&DOS_DATE.to_le_bytes());
            cd.extend_from_slice(&r.crc32.to_le_bytes());
            cd.extend_from_slice(&clamp(r.compressed_size).to_le_bytes());
            cd.extend_from_slice(&clamp(r.uncompressed_size).to_le_bytes());
            cd.extend_from_slice(&(r.name.len() as u16).to_le_bytes());
            let extra_len = if extra.is_empty() { 0 } else { 4 + extra.len() };
            cd.extend_from_slice(&(extra_len as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            cd.extend_from_slice(&r.external_attributes.to_le_bytes());
            cd.extend_from_slice(&clamp(r.offset).to_le_bytes());
            cd.extend_from_slice(r.name.as_bytes());
            if !extra.is_empty() {
                cd.extend_from_slice(&ZIP64_EXTRA.to_le_bytes());
                cd.extend_from_slice(&(extra.len() as u16).to_le_bytes());
                cd.extend_from_slice(&extra);
            }
        }
        self.inner.write_all(&cd)?;
        let cd_size = cd.len() as u64;
        let count = self.central.len() as u64;
        let eocd64_offset = cd_offset + cd_size;

        let needs_zip64 = count >= 0xFFFF || cd_size >= 0xFFFF_FFFF || cd_offset >= 0xFFFF_FFFF;
        let mut tail = Vec::new();
        if needs_zip64 {
            tail.extend_from_slice(&SIG_EOCD64.to_le_bytes());
            tail.extend_from_slice(&44u64.to_le_bytes());
            tail.extend_from_slice(&VERSION_MADE_BY.to_le_bytes());
            tail.extend_from_slice(&45u16.to_le_bytes());
            tail.extend_from_slice(&0u32.to_le_bytes());
            tail.extend_from_slice(&0u32.to_le_bytes());
            tail.extend_from_slice(&count.to_le_bytes());
            tail.extend_from_slice(&count.to_le_bytes());
            tail.extend_from_slice(&cd_size.to_le_bytes());
            tail.extend_from_slice(&cd_offset.to_le_bytes());
            tail.extend_from_slice(&SIG_EOCD64_LOCATOR.to_le_bytes());
            tail.extend_from_slice(&0u32.to_le_bytes());
            tail.extend_from_slice(&eocd64_offset.to_le_bytes());
            tail.extend_from_slice(&1u32.to_le_bytes());
        }
        let c16 = if needs_zip64 { 0xFFFF } else { count as u16 };
        tail.extend_from_slice(&SIG_EOCD.to_le_bytes());
        tail.extend_from_slice(&0u16.to_le_bytes());
        tail.extend_from_slice(&0u16.to_le_bytes());
        tail.extend_from_slice(&c16.to_le_bytes());
        tail.extend_from_slice(&c16.to_le_bytes());
        tail.extend_from_slice(
            &(if needs_zip64 {
                0xFFFF_FFFF
            } else {
                cd_size as u32
            })
            .to_le_bytes(),
        );
        tail.extend_from_slice(
            &(if needs_zip64 {
                0xFFFF_FFFF
            } else {
                cd_offset as u32
            })
            .to_le_bytes(),
        );
        tail.extend_from_slice(&0u16.to_le_bytes());
        self.inner.write_all(&tail)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::base64;
    use std::io::Cursor;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    fn sample_archive() -> Vec<u8> {
        let mut w = ZipWriter::new(Vec::new());
        w.add_directory("Payload/", 0o755).unwrap();
        w.add_directory("Payload/App.app", 0o755).unwrap();
        w.add_file("Payload/App.app/App", &[0xCF; 5000], 0o755, true)
            .unwrap();
        w.add_file("Payload/App.app/Info.plist", b"<plist/>", 0o644, true)
            .unwrap();
        w.add_file("Payload/App.app/empty", b"", 0o644, true)
            .unwrap();
        w.add_symlink("Payload/App.app/link", "App").unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn roundtrip() {
        let bytes = sample_archive();
        let mut r = ZipReader::new(Cursor::new(bytes)).unwrap();
        let names: Vec<_> = r.entries().iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names,
            [
                "Payload/",
                "Payload/App.app/",
                "Payload/App.app/App",
                "Payload/App.app/Info.plist",
                "Payload/App.app/empty",
                "Payload/App.app/link"
            ]
        );
        assert!(r.entries()[0].is_dir());
        assert_eq!(r.entries()[2].method, METHOD_DEFLATE);
        assert_eq!(r.entries()[2].unix_mode(), Some(S_IFREG | 0o755));
        assert!(r.entries()[5].is_symlink());
        assert_eq!(r.read(2).unwrap(), vec![0xCF; 5000]);
        assert_eq!(r.read(3).unwrap(), b"<plist/>");
        assert_eq!(r.read(4).unwrap(), b"");
        assert_eq!(r.read(5).unwrap(), b"App");
    }

    #[test]
    fn detects_corruption() {
        let mut bytes = sample_archive();
        // Flip a byte inside the first stored payload ("<plist/>").
        let pos = bytes.windows(8).position(|w| w == b"<plist/>").unwrap();
        bytes[pos] ^= 1;
        let mut r = ZipReader::new(Cursor::new(bytes)).unwrap();
        assert!(r.read(3).unwrap_err().0.contains("CRC"));
    }

    #[test]
    fn rejects_sizes_past_end_without_allocating() {
        let mut bytes = sample_archive();
        // Patch the compressed size of the first central entry to 4 GiB - 2.
        let cd = bytes
            .windows(4)
            .position(|w| w == SIG_CENTRAL.to_le_bytes())
            .unwrap();
        bytes[cd + 20..cd + 24].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        let mut r = ZipReader::new(Cursor::new(bytes)).unwrap();
        assert!(r.read(0).unwrap_err().0.contains("past the end"));
    }

    /// Archive made by Python's `zipfile` (deflated + stored, with a comment).
    #[test]
    fn reads_python_zipfile_output() {
        let bytes = base64::decode(include_str!("testdata/python.zip.b64")).unwrap();
        let mut r = ZipReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(r.entries().len(), 3);
        let idx = |n: &str| r.entries().iter().position(|e| e.name == n).unwrap();
        let (a, b, c) = (idx("dir/a.txt"), idx("b.bin"), idx("dir/"));
        assert_eq!(r.read(a).unwrap(), "hello ".repeat(100).as_bytes());
        assert_eq!(r.read(b).unwrap(), (0u8..=255).collect::<Vec<_>>());
        assert!(r.entries()[c].is_dir());
    }

    #[test]
    fn safe_paths() {
        assert_eq!(
            safe_relative_path("Payload/A.app/Info.plist"),
            Some(PathBuf::from("Payload/A.app/Info.plist"))
        );
        assert_eq!(
            safe_relative_path("Payload/"),
            Some(PathBuf::from("Payload"))
        );
        assert_eq!(safe_relative_path("./a//b"), Some(PathBuf::from("a/b")));
        for bad in [
            "",
            "/etc/passwd",
            "a/../../b",
            "..",
            "a\\b",
            "C:/x",
            "./",
            "a\0b",
        ] {
            assert_eq!(safe_relative_path(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(ZipReader::new(Cursor::new(b"not a zip".to_vec())).is_err());
        let mut bytes = sample_archive();
        let n = bytes.len();
        bytes.truncate(n - 30);
        assert!(ZipReader::new(Cursor::new(bytes)).is_err());
    }
}
