//! `install --sidestore` and `install --sideload-app`: an IPA attached to a
//! GitHub release (SPEC Sections 7.7, 7.8).

use std::path::{Path, PathBuf};

use crate::formats::json;
use crate::net::http::{Client, Request};
use crate::{Error, ErrorCode, Result};

pub const RELEASES_URL: &str = "https://api.github.com/repos/SideStore/SideStore/releases/latest";
pub const ASSET_NAME: &str = "SideStore.ipa";
pub const MAX_IPA_BYTES: usize = 1 << 30;

/// The release tag the iOS app workflow publishes `Sideload.ipa` under
/// (SPEC Section 7.8).
pub const SIDELOAD_APP_TAG: &str = "sideload-app";

/// Where an app's IPA is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// For messages, e.g. `SideStore`.
    pub name: &'static str,
    /// GitHub API URL returning one release.
    pub release_url: &'static str,
    /// Exact asset name.
    pub asset: &'static str,
}

/// The latest SideStore release (SPEC Section 7.7).
pub const SIDESTORE: Source = Source {
    name: "SideStore",
    release_url: RELEASES_URL,
    asset: ASSET_NAME,
};

/// The Sideload iOS app (SPEC Section 7.8, `ios/SPEC.md`).
pub const SIDELOAD_APP: Source = Source {
    name: "the Sideload app",
    release_url: "https://api.github.com/repos/kt3k/sideload/releases/tags/sideload-app",
    asset: "Sideload.ipa",
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub asset: String,
    pub download_url: String,
    pub size: Option<u64>,
    pub sha256: Option<[u8; 32]>,
}

fn failed(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::DownloadFailed, msg)
}

/// Extracts the `SideStore.ipa` asset from a `releases/latest` response.
pub fn parse_release(body: &str) -> Result<Release> {
    parse_release_asset(body, ASSET_NAME)
}

/// Extracts the asset named `asset_name` from a GitHub release response.
pub fn parse_release_asset(body: &str, asset_name: &str) -> Result<Release> {
    let v = json::parse(body).map_err(|e| failed(format!("invalid GitHub API response: {e}")))?;
    let tag = v
        .get("tag_name")
        .and_then(json::Value::as_str)
        .unwrap_or("(unknown)")
        .to_owned();
    let assets = v
        .get("assets")
        .and_then(json::Value::as_array)
        .ok_or_else(|| failed("GitHub API response has no assets"))?;
    let asset = assets
        .iter()
        .find(|a| a.get("name").and_then(json::Value::as_str) == Some(asset_name))
        .ok_or_else(|| failed(format!("release {tag} has no {asset_name} asset")))?;
    let download_url = asset
        .get("browser_download_url")
        .and_then(json::Value::as_str)
        .filter(|u| u.starts_with("https://"))
        .ok_or_else(|| {
            failed(format!(
                "{asset_name} in release {tag} has no HTTPS download URL"
            ))
        })?
        .to_owned();
    let size = asset
        .get("size")
        .and_then(json::Value::as_f64)
        .filter(|s| *s >= 0.0 && s.fract() == 0.0)
        .map(|s| s as u64);
    let sha256 = match asset.get("digest").and_then(json::Value::as_str) {
        Some(d) => match d.strip_prefix("sha256:") {
            Some(hex) => {
                Some(parse_hex32(hex).ok_or_else(|| failed(format!("invalid digest `{d}`")))?)
            }
            None => None, // Unknown algorithm: rely on HTTPS.
        },
        None => None,
    };
    Ok(Release {
        tag,
        asset: asset_name.to_owned(),
        download_url,
        size,
        sha256,
    })
}

fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Checks a downloaded body against the release metadata.
pub fn verify(release: &Release, body: &[u8]) -> Result<()> {
    if let Some(size) = release.size {
        if body.len() as u64 != size {
            return Err(failed(format!(
                "{} size mismatch: expected {size} bytes, got {}",
                release.asset,
                body.len()
            )));
        }
    }
    match release.sha256 {
        Some(expected) => {
            if crate::crypto::sha256(body) != expected {
                return Err(failed(format!("{} SHA-256 digest mismatch", release.asset)));
            }
        }
        None => crate::output::debug(format!(
            "release {} publishes no SHA-256 digest for {}; relying on HTTPS",
            release.tag, release.asset
        )),
    }
    Ok(())
}

pub fn http_client() -> Result<Client> {
    Client::new(
        &format!("sideload/{}", crate::commands::version::VERSION),
        &[],
    )
    .map_err(|e| failed(e.to_string()))
}

/// Downloads the latest SideStore release into `dir`, returning the IPA path.
pub fn download_latest(client: &Client, dir: &Path) -> Result<(PathBuf, Release)> {
    download(client, dir, &SIDESTORE)
}

/// Downloads `source`'s IPA into `dir`, returning its path.
pub fn download(client: &Client, dir: &Path, source: &Source) -> Result<(PathBuf, Release)> {
    let resp = client
        .send(
            &Request::get(source.release_url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .max_body(4 * 1024 * 1024),
        )
        .map_err(|e| failed(format!("cannot reach the GitHub API: {e}")))?;
    if !resp.is_success() {
        return Err(failed(format!(
            "GitHub API returned HTTP {} for {}",
            resp.status, source.release_url
        )));
    }
    let release = parse_release_asset(&String::from_utf8_lossy(&resp.body), source.asset)?;
    crate::output::info(format!("Downloading {} ({})...", source.name, release.tag));

    let resp = client
        .send(
            &Request::get(&release.download_url)
                .header("Accept", "application/octet-stream")
                .max_body(MAX_IPA_BYTES),
        )
        .map_err(|e| failed(format!("cannot download {}: {e}", source.asset)))?;
    if !resp.is_success() {
        return Err(failed(format!(
            "downloading {} returned HTTP {}",
            source.asset, resp.status
        )));
    }
    verify(&release, &resp.body)?;

    let path = dir.join(source.asset);
    std::fs::write(&path, &resp.body)
        .map_err(|e| failed(format!("cannot write `{}`: {e}", path.display())))?;
    Ok((path, release))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "tag_name": "0.6.1", "prerelease": false,
      "assets": [
        {"name": "SideStore.ipa.sha256", "size": 64, "browser_download_url": "https://github.com/x/1"},
        {"name": "SideStore.ipa", "size": 3,
         "digest": "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         "browser_download_url": "https://github.com/SideStore/SideStore/releases/download/0.6.1/SideStore.ipa"}
      ]
    }"#;

    #[test]
    fn selects_the_ipa_asset_by_exact_name() {
        let r = parse_release(SAMPLE).unwrap();
        assert_eq!(r.tag, "0.6.1");
        assert!(r.download_url.ends_with("/0.6.1/SideStore.ipa"));
        assert_eq!(r.size, Some(3));
        assert_eq!(r.sha256, Some(crate::crypto::sha256(b"abc")));
    }

    #[test]
    fn verification() {
        let r = parse_release(SAMPLE).unwrap();
        assert!(verify(&r, b"abc").is_ok());
        assert_eq!(
            verify(&r, b"abd").unwrap_err().code,
            ErrorCode::DownloadFailed
        );
        assert_eq!(
            verify(&r, b"abcd").unwrap_err().code,
            ErrorCode::DownloadFailed
        );
        let no_digest = Release {
            sha256: None,
            size: None,
            ..r
        };
        assert!(verify(&no_digest, b"anything").is_ok());
    }

    #[test]
    fn rejects_missing_or_insecure_assets() {
        let missing = r#"{"tag_name":"1.0","assets":[{"name":"Other.ipa","browser_download_url":"https://x"}]}"#;
        assert!(
            parse_release(missing)
                .unwrap_err()
                .message
                .contains("no SideStore.ipa")
        );
        let http = r#"{"tag_name":"1.0","assets":[{"name":"SideStore.ipa","browser_download_url":"http://x"}]}"#;
        assert!(parse_release(http).is_err());
        let bad_digest = r#"{"assets":[{"name":"SideStore.ipa","browser_download_url":"https://x","digest":"sha256:zz"}]}"#;
        assert!(parse_release(bad_digest).is_err());
        assert!(parse_release("not json").is_err());
    }

    #[test]
    fn selects_the_sideload_app_asset() {
        let body = r#"{"tag_name":"sideload-app","prerelease":true,"assets":[
          {"name":"Sideload.ipa.sha256","browser_download_url":"https://x/1"},
          {"name":"Sideload.ipa","size":3,"browser_download_url":"https://github.com/kt3k/sideload/releases/download/sideload-app/Sideload.ipa"}]}"#;
        let r = parse_release_asset(body, SIDELOAD_APP.asset).unwrap();
        assert_eq!(r.tag, SIDELOAD_APP_TAG);
        assert_eq!(r.asset, "Sideload.ipa");
        assert!(r.download_url.ends_with("/sideload-app/Sideload.ipa"));
        assert!(SIDELOAD_APP.release_url.ends_with(SIDELOAD_APP_TAG));
        let e = verify(&r, b"abcd").unwrap_err();
        assert!(e.message.contains("Sideload.ipa"), "{}", e.message);
        assert!(parse_release_asset(SAMPLE, SIDELOAD_APP.asset).is_err());
    }

    #[test]
    fn unknown_digest_algorithm_is_ignored() {
        let other = r#"{"assets":[{"name":"SideStore.ipa","browser_download_url":"https://x","digest":"sha512:00"}]}"#;
        assert_eq!(parse_release(other).unwrap().sha256, None);
    }
}
