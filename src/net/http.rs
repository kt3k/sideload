//! Minimal blocking HTTP/1.1 client over rustls.
//!
//! - One request per connection (`Connection: close`).
//! - Bodies: `Content-Length`, `chunked`, or read-to-EOF.
//! - Redirects (301/302/303/307/308) are followed for GET, HTTPS only.
//! - `HTTPS_PROXY` / `https_proxy` (an `http://host:port` proxy, CONNECT
//!   tunnel) and `NO_PROXY` are honored.
//! - Extra trust anchors can be added from a PEM file named by
//!   `SSL_CERT_FILE` (for corporate TLS-intercepting proxies).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};

use super::{NetError, NetResult};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Responses larger than this fail with an error.
    pub max_body: usize,
}

impl Request {
    pub fn get(url: impl Into<String>) -> Request {
        Request {
            method: "GET",
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            max_body: 64 * 1024 * 1024,
        }
    }

    pub fn post(url: impl Into<String>, body: Vec<u8>) -> Request {
        Request {
            method: "POST",
            body,
            ..Request::get(url)
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Request {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn max_body(mut self, bytes: usize) -> Request {
        self.max_body = bytes;
        self
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The URL that produced this response (after redirects).
    pub url: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Parsed `https://host[:port]/path?query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(url: &str) -> NetResult<Url> {
        let rest = url.strip_prefix("https://").ok_or_else(|| {
            NetError::transport(format!("only https:// URLs are supported: {url}"))
        })?;
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_owned()),
        };
        let path = path.split('#').next().unwrap_or("/").to_owned();
        if authority.contains('@') {
            return Err(NetError::transport("credentials in URLs are not supported"));
        }
        let (host, port) = split_host_port(authority, 443)?;
        Ok(Url { host, port, path })
    }

    /// Resolves a `Location` header against this URL.
    pub fn join(&self, location: &str) -> NetResult<String> {
        if location.starts_with("https://") {
            Ok(location.to_owned())
        } else if location.starts_with("http://") {
            Err(NetError::transport(
                "refusing to follow a redirect to plain HTTP",
            ))
        } else if let Some(rest) = location.strip_prefix("//") {
            Ok(format!("https://{rest}"))
        } else if location.starts_with('/') {
            Ok(format!("https://{}{location}", self.authority()))
        } else {
            let base = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
            Ok(format!("https://{}{base}{location}", self.authority()))
        }
    }

    fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn split_host_port(authority: &str, default_port: u16) -> NetResult<(String, u16)> {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
            let port = p
                .parse()
                .map_err(|_| NetError::transport(format!("invalid port in `{authority}`")))?;
            (h, port)
        }
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(NetError::transport("missing host"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

// ---------------------------------------------------------------- TLS

fn root_store(extra_roots: &[Vec<u8>]) -> NetResult<rustls::RootCertStore> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in extra_roots {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| NetError::transport(format!("invalid trust anchor: {e}")))?;
    }
    if let Some(path) = std::env::var_os("SSL_CERT_FILE").filter(|v| !v.is_empty()) {
        let pem = std::fs::read_to_string(&path)
            .map_err(|e| NetError::transport(format!("cannot read SSL_CERT_FILE: {e}")))?;
        for der in pem_certificates(&pem) {
            // Ignore individual unparsable entries, as OpenSSL does.
            let _ = roots.add(CertificateDer::from(der));
        }
    }
    Ok(roots)
}

fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let body = &rest[start + BEGIN.len()..];
        let Some(stop) = body.find(END) else { break };
        if let Ok(der) = crate::formats::base64::decode(&body[..stop]) {
            out.push(der);
        }
        rest = &body[stop + END.len()..];
    }
    out
}

/// TLS configuration shared by all requests of a client.
#[derive(Clone)]
pub struct Client {
    config: Arc<rustls::ClientConfig>,
    user_agent: String,
}

impl Client {
    /// Trusts the Mozilla root set (`webpki-roots`), plus `extra_roots`
    /// (DER) and `SSL_CERT_FILE`.
    pub fn new(user_agent: &str, extra_roots: &[Vec<u8>]) -> NetResult<Client> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| NetError::transport(format!("TLS setup failed: {e}")))?
            .with_root_certificates(root_store(extra_roots)?)
            .with_no_client_auth();
        Ok(Client {
            config: Arc::new(config),
            user_agent: user_agent.to_owned(),
        })
    }

    /// Sends `req`, following redirects for GET requests.
    pub fn send(&self, req: &Request) -> NetResult<Response> {
        let mut url = req.url.clone();
        for _ in 0..=MAX_REDIRECTS {
            let resp = self.send_once(req, &url)?;
            let redirect =
                matches!(resp.status, 301 | 302 | 303 | 307 | 308) && req.method == "GET";
            match (redirect, resp.header("location")) {
                (true, Some(loc)) => url = Url::parse(&url)?.join(loc)?,
                _ => return Ok(resp),
            }
        }
        Err(NetError::transport(format!(
            "too many redirects from {}",
            req.url
        )))
    }

    fn send_once(&self, req: &Request, url_str: &str) -> NetResult<Response> {
        let url = Url::parse(url_str)?;
        let tcp = connect(&url)?;
        let server_name = ServerName::try_from(url.host.clone())
            .map_err(|_| NetError::transport(format!("invalid host name `{}`", url.host)))?;
        let conn = rustls::ClientConnection::new(self.config.clone(), server_name)
            .map_err(|e| NetError::transport(format!("TLS setup failed: {e}")))?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);

        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            req.method,
            url.path,
            url.authority()
        );
        let has = |name: &str| {
            req.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        if !has("user-agent") {
            head.push_str(&format!("User-Agent: {}\r\n", self.user_agent));
        }
        if !has("accept") {
            head.push_str("Accept: */*\r\n");
        }
        for (k, v) in &req.headers {
            if k.contains(['\r', '\n', ':']) || v.contains(['\r', '\n']) {
                return Err(NetError::transport(format!("invalid header `{k}`")));
            }
            if k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if req.method != "GET" || !req.body.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
        }
        head.push_str("Connection: close\r\n\r\n");

        let io = |e: std::io::Error| NetError::transport(format!("{}: {e}", url.host));
        tls.write_all(head.as_bytes()).map_err(io)?;
        tls.write_all(&req.body).map_err(io)?;
        tls.flush().map_err(io)?;

        let mut reader = BufReader::new(tls);
        let (status, headers) = read_head(&mut reader).map_err(|e| e.context(&url.host))?;
        let body = if req.method == "HEAD"
            || status == 204
            || status == 304
            || (100..200).contains(&status)
        {
            Vec::new()
        } else {
            read_body(&mut reader, &headers, req.max_body).map_err(|e| e.context(&url.host))?
        };
        Ok(Response {
            status,
            headers,
            body,
            url: url_str.to_owned(),
        })
    }
}

// ---------------------------------------------------------------- connection and proxy

fn proxy_for(host: &str) -> Option<String> {
    let proxy = ["HTTPS_PROXY", "https_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))?;
    let no_proxy = ["NO_PROXY", "no_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .unwrap_or_default();
    if bypasses_proxy(host, &no_proxy) {
        None
    } else {
        Some(proxy)
    }
}

/// `NO_PROXY` matching: `*`, exact hosts, and domain suffixes
/// (`example.com`, `.example.com`).
fn bypasses_proxy(host: &str, no_proxy: &str) -> bool {
    no_proxy
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|entry| {
            let entry = entry
                .split(':')
                .next()
                .unwrap_or(entry)
                .trim_start_matches("*.")
                .trim_start_matches('.');
            entry == "*" || host == entry || host.ends_with(&format!(".{entry}"))
        })
}

fn connect(url: &Url) -> NetResult<TcpStream> {
    let target = format!("{}:{}", url.host, url.port);
    let io = |e: std::io::Error| NetError::transport(format!("cannot connect to {target}: {e}"));
    let stream = match proxy_for(&url.host) {
        None => TcpStream::connect(&target).map_err(io)?,
        Some(proxy) => {
            let authority = proxy
                .strip_prefix("http://")
                .ok_or_else(|| NetError::transport("HTTPS_PROXY must be an http:// URL"))?
                .trim_end_matches('/');
            let (phost, pport) = split_host_port(authority, 80)?;
            let mut s = TcpStream::connect((phost.as_str(), pport)).map_err(io)?;
            s.set_read_timeout(Some(TIMEOUT)).map_err(io)?;
            write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").map_err(io)?;
            let mut r = BufReader::new(s);
            let (status, _) = read_head(&mut r)?;
            if status != 200 {
                return Err(NetError::transport(format!(
                    "proxy refused CONNECT to {target} (HTTP {status})"
                )));
            }
            if !r.buffer().is_empty() {
                return Err(NetError::transport(
                    "proxy sent data before the TLS handshake",
                ));
            }
            r.into_inner()
        }
    };
    stream.set_read_timeout(Some(TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(io)?;
    Ok(stream)
}

// ---------------------------------------------------------------- parsing

fn read_line(r: &mut impl BufRead, budget: &mut usize) -> NetResult<String> {
    let mut line = Vec::new();
    let n = r
        .take(*budget as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|e| NetError::transport(e.to_string()))?;
    if n == 0 {
        return Err(NetError::transport("connection closed before the response"));
    }
    if n > *budget {
        return Err(NetError::transport("response headers too large"));
    }
    *budget -= n;
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| NetError::transport("non-UTF-8 response header"))
}

fn read_head(r: &mut impl BufRead) -> NetResult<(u16, Vec<(String, String)>)> {
    let mut budget = MAX_HEADER_BYTES;
    loop {
        let status_line = read_line(r, &mut budget)?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .filter(|_| version.starts_with("HTTP/1."))
            .ok_or_else(|| NetError::transport(format!("invalid status line `{status_line}`")))?;
        let mut headers = Vec::new();
        loop {
            let line = read_line(r, &mut budget)?;
            if line.is_empty() {
                break;
            }
            let (k, v) = line
                .split_once(':')
                .ok_or_else(|| NetError::transport(format!("invalid header line `{line}`")))?;
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
        // Skip interim 1xx responses (except 101, which we never request).
        if status == 100 || status == 102 || status == 103 {
            continue;
        }
        return Ok((status, headers));
    }
}

fn read_body(r: &mut impl BufRead, headers: &[(String, String)], max: usize) -> NetResult<Vec<u8>> {
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let too_large = || NetError::transport(format!("response body exceeds {max} bytes"));
    let io = |e: std::io::Error| NetError::transport(e.to_string());

    if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        let mut body = Vec::new();
        loop {
            let mut budget = 1024;
            let line = read_line(r, &mut budget)?;
            let size_str = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| NetError::transport(format!("invalid chunk size `{size_str}`")))?;
            if size == 0 {
                // Trailers until an empty line.
                let mut budget = MAX_HEADER_BYTES;
                while !read_line(r, &mut budget)?.is_empty() {}
                return Ok(body);
            }
            if body.len().saturating_add(size) > max {
                return Err(too_large());
            }
            let start = body.len();
            body.resize(start + size, 0);
            r.read_exact(&mut body[start..]).map_err(io)?;
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf).map_err(io)?;
            if &crlf != b"\r\n" {
                return Err(NetError::transport("malformed chunked body"));
            }
        }
    }
    if let Some(len) = get("content-length") {
        let len: usize = len
            .parse()
            .map_err(|_| NetError::transport("invalid Content-Length"))?;
        if len > max {
            return Err(too_large());
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).map_err(io)?;
        return Ok(body);
    }
    let mut body = Vec::new();
    let n = r.take(max as u64 + 1).read_to_end(&mut body).map_err(io)?;
    if n > max {
        return Err(too_large());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn url_parsing() {
        assert_eq!(
            Url::parse("https://API.github.com/repos/x?y=1#frag").unwrap(),
            Url {
                host: "api.github.com".into(),
                port: 443,
                path: "/repos/x?y=1".into()
            }
        );
        assert_eq!(
            Url::parse("https://h:8443").unwrap(),
            Url {
                host: "h".into(),
                port: 8443,
                path: "/".into()
            }
        );
        assert_eq!(Url::parse("https://h?q").unwrap().path, "/?q");
        for bad in [
            "http://h/",
            "ftp://h",
            "https://",
            "https://u:p@h/",
            "https://h:x/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn redirect_resolution() {
        let base = Url::parse("https://a.example/dir/file?x").unwrap();
        assert_eq!(
            base.join("https://b.example/z").unwrap(),
            "https://b.example/z"
        );
        assert_eq!(base.join("/abs").unwrap(), "https://a.example/abs");
        assert_eq!(base.join("rel").unwrap(), "https://a.example/dir/rel");
        assert_eq!(base.join("//c.example/p").unwrap(), "https://c.example/p");
        assert!(base.join("http://insecure.example/").is_err());
    }

    #[test]
    fn no_proxy_matching() {
        let list = "localhost, .internal.example ,corp.example:8080,127.0.0.1";
        assert!(bypasses_proxy("localhost", list));
        assert!(bypasses_proxy("a.internal.example", list));
        assert!(bypasses_proxy("x.corp.example", list));
        assert!(!bypasses_proxy("example.com", list));
        assert!(!bypasses_proxy("notcorp.example", list));
        assert!(bypasses_proxy("anything", "*"));
    }

    #[test]
    fn parses_content_length_response() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhelloEXTRA";
        let mut r = Cursor::new(&raw[..]);
        let (status, headers) = read_head(&mut r).unwrap();
        assert_eq!(status, 200);
        assert_eq!(read_body(&mut r, &headers, 100).unwrap(), b"hello");
        assert!(read_body(&mut Cursor::new(&b"hello"[..]), &headers, 4).is_err());
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
        let mut r = Cursor::new(&raw[..]);
        let (_, headers) = read_head(&mut r).unwrap();
        assert_eq!(read_body(&mut r, &headers, 100).unwrap(), b"hello world");
        let mut r = Cursor::new(&raw[..]);
        let (_, headers) = read_head(&mut r).unwrap();
        assert!(read_body(&mut r, &headers, 8).is_err());
    }

    #[test]
    fn parses_eof_delimited_response() {
        let raw = b"HTTP/1.0 404 Not Found\r\n\r\nnope";
        let mut r = Cursor::new(&raw[..]);
        let (status, headers) = read_head(&mut r).unwrap();
        assert_eq!(status, 404);
        assert_eq!(read_body(&mut r, &headers, 100).unwrap(), b"nope");
    }

    #[test]
    fn rejects_bad_heads() {
        for raw in [
            &b"garbage\r\n\r\n"[..],
            b"HTTP/2 200\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
            b"",
        ] {
            assert!(read_head(&mut Cursor::new(raw)).is_err());
        }
    }

    #[test]
    fn extracts_pem_certificates() {
        let pem = include_str!("../formats/testdata/openssl_cert.pem");
        let both = format!("junk\n{pem}\n{pem}");
        assert_eq!(pem_certificates(&both).len(), 2);
    }
}
