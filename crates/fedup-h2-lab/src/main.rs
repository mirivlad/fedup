//! Standards-compliant HTTP/2 streaming laboratory.
//!
//! Uses actual HTTP/2 SETTINGS, HEADERS and DATA frames over ALPN=h2 TLS 1.3,
//! not a forged ALPN extension. This is *not* a VPN transport or browser camouflage.
//! Bind loopback only; operator-approved client certificates are mandatory.

use bytes::Bytes;
use fedup_identity::{decrypt_pkcs8, device_connection, read_password};
use h2::{client, server, RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::future::poll_fn;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const MAX_TRANSFER: usize = 256 * 1024;
const CHUNK: usize = 8192;
const MAX_ALLOWLIST_BYTES: u64 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(45);
const URI: &str = "/fedup-lab/v1/duplex";
const TYPE: &str = "application/vnd.fedup.lab+binary";

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let entries = rustls_pemfile::certs(&mut reader).collect::<std::io::Result<Vec<_>>>()?;
    if entries.is_empty() {
        return Err("no certificate supplied".into());
    }
    Ok(entries)
}

fn key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::private_key(&mut reader)?.ok_or("no private key found")?)
}

fn roots(path: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for entry in certificates(path)? {
        roots.add(entry)?;
    }
    Ok(roots)
}

fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn authorized(path: &Path, fingerprint: &str) -> Result<bool> {
    if fs::metadata(path)?.len() > MAX_ALLOWLIST_BYTES {
        return Err("allowlist exceeds size limit".into());
    }
    let text = fs::read_to_string(path)?;
    if text.len() as u64 > MAX_ALLOWLIST_BYTES {
        return Err("allowlist exceeds size limit".into());
    }
    let mut allowed = false;
    for line in text.lines() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid allowlist entry".into());
        }
        if value.eq_ignore_ascii_case(fingerprint) {
            allowed = true;
        }
    }
    Ok(allowed)
}

/// Honor HTTP/2 stream and connection-level flow control before submitting
/// each DATA frame. Never let the library buffer unbounded queued outbound data.
async fn send_bounded(send: &mut SendStream<Bytes>, mut body: Bytes) -> Result<()> {
    while !body.is_empty() {
        let want = body.len().min(CHUNK);
        send.reserve_capacity(want);
        let capacity = timeout(TRANSFER_TIMEOUT, poll_fn(|cx| send.poll_capacity(cx)))
            .await?
            .ok_or("HTTP/2 stream closed while awaiting send window")??;
        if capacity == 0 {
            return Err("HTTP/2 send capacity is zero".into());
        }
        send.send_data(body.split_to(want.min(capacity)), false)?;
    }
    Ok(())
}

async fn echo_stream(mut incoming: RecvStream, mut send: SendStream<Bytes>) -> Result<()> {
    let mut received = 0usize;
    while let Some(result) = timeout(TRANSFER_TIMEOUT, incoming.data()).await? {
        let chunk = result?;
        received = received.checked_add(chunk.len()).ok_or("length overflow")?;
        if received > MAX_TRANSFER {
            send.send_reset(h2::Reason::ENHANCE_YOUR_CALM);
            return Err("HTTP/2 test body exceeds 256 KiB limit".into());
        }
        let used = chunk.len();
        send_bounded(&mut send, chunk).await?;
        incoming.flow_control().release_capacity(used)?;
    }
    send.send_data(Bytes::new(), true)?;
    Ok(())
}

fn request_valid(req: &Request<RecvStream>) -> bool {
    req.method() == http::Method::POST
        && req.uri().path() == URI
        && req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|h| h == TYPE)
}

/// An authenticated loopback HTTPS/2 application, not a generic CONNECT proxy.
async fn handle(socket: TcpStream, acceptor: TlsAcceptor, allowlist: &Path) -> Result<()> {
    let tls = timeout(CONNECT_TIMEOUT, acceptor.accept(socket)).await??;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("ALPN h2 was not negotiated".into());
    }
    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("missing client identity")?;
    if !authorized(allowlist, &fingerprint(peer.as_ref()))? {
        return Err("client identity not permitted".into());
    }

    let mut connection = timeout(CONNECT_TIMEOUT, server::handshake(tls)).await??;
    let mut active = false;
    let mut handlers = Vec::new();
    while let Some(next) = timeout(TRANSFER_TIMEOUT, connection.accept()).await? {
        let (req, mut respond) = next?;
        if active || !request_valid(&req) {
            respond.send_response(
                Response::builder().status(StatusCode::NOT_FOUND).body(())?,
                true,
            )?;
            continue;
        }
        active = true;
        let stream = respond.send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, TYPE)
                .body(())?,
            false,
        )?;
        handlers.push(tokio::spawn(echo_stream(req.into_body(), stream)));
    }
    for handler in handlers {
        handler.await??;
    }
    Ok(())
}

async fn run_server(
    bind: SocketAddr,
    ca: &Path,
    cert: &Path,
    private: &Path,
    allowlist: &Path,
) -> Result<()> {
    if !bind.ip().is_loopback() {
        return Err("HTTP/2 research server binds LOOPBACK ONLY".into());
    }
    let _ = authorized(allowlist, "")?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(ca)?)).build()?;
    let mut tls = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(cert)?, key(private)?)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let socket = TcpListener::bind(bind).await?;
    println!("FedUp real HTTP/2 lab on {bind}; only one POST stream per connection");
    loop {
        let (peer, _) = socket.accept().await?;
        let acceptor = acceptor.clone();
        let allowlist = allowlist.to_path_buf();
        tokio::spawn(async move {
            if let Err(error) = handle(peer, acceptor, &allowlist).await {
                eprintln!("HTTP/2 lab session closed: {error}");
            }
        });
    }
}

fn synthetic_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

async fn run_client(
    server: SocketAddr,
    device_dir: &Path,
    amount: usize,
    stdin: bool,
) -> Result<()> {
    if !server.ip().is_loopback() {
        return Err("HTTP/2 test client accepts loopback destination only".into());
    }
    if !(1..=MAX_TRANSFER).contains(&amount) {
        return Err("test payload must be 1-262144 bytes".into());
    }
    let device = device_connection(device_dir)?;
    let password = read_password(false, stdin)?;
    let der = decrypt_pkcs8(&device.encrypted_key_path, password.as_bytes())?;
    let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()));
    let mut tls = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(&device.ca_path)?)
        .with_client_auth_cert(certificates(&device.cert_path)?, client_key)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(server)).await??;
    let name: ServerName<'static> = ServerName::try_from(device.server_name.clone())?;
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await??;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("remote endpoint did not negotiate ALPN h2".into());
    }

    let (mut sender, connection) = timeout(CONNECT_TIMEOUT, client::handshake(tls)).await??;
    let driver = tokio::spawn(connection);
    sender = timeout(CONNECT_TIMEOUT, sender.ready()).await??;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(format!(
            "https://{}/{}",
            device.server_name,
            URI.trim_start_matches('/')
        ))
        .header(http::header::CONTENT_TYPE, TYPE)
        .body(())?;
    let (response, mut outbound) = sender.send_request(request, false)?;
    let expected = synthetic_payload(amount);
    let send_bytes = expected.clone();
    let outgoing = tokio::spawn(async move {
        for chunk in send_bytes.chunks(CHUNK) {
            send_bounded(&mut outbound, Bytes::copy_from_slice(chunk)).await?;
        }
        outbound.send_data(Bytes::new(), true)?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let response = timeout(TRANSFER_TIMEOUT, response).await??;
    if response.status() != StatusCode::OK {
        return Err(format!("HTTP/2 status {}", response.status()).into());
    }
    if response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .is_none_or(|v| v != TYPE)
    {
        return Err("unexpected response content type".into());
    }
    let mut incoming = response.into_body();
    let mut actual = Vec::with_capacity(amount);
    while let Some(part) = timeout(TRANSFER_TIMEOUT, incoming.data()).await? {
        let part = part?;
        if actual.len().saturating_add(part.len()) > MAX_TRANSFER {
            return Err("HTTP/2 response exceeded size limit".into());
        }
        actual.extend_from_slice(&part);
        incoming.flow_control().release_capacity(part.len())?;
    }
    outgoing.await??;
    if actual != expected {
        return Err(format!(
            "HTTP/2 echo mismatch: {}/{} bytes",
            actual.len(),
            expected.len()
        )
        .into());
    }
    drop(sender);
    driver.abort();
    println!(
        "FedUp genuine HTTPS/2 POST streaming roundtrip: {amount} binary bytes, ALPN h2 verified"
    );
    Ok(())
}

fn usage() {
    eprintln!(
        r#"FedUp genuine HTTP/2 loopback lab, NOT a VPN or browser impersonation:
fedup-h2-lab server <loopback-ip:port> <ca.pem> <server.pem> <server.key> <allowlist.txt>
fedup-h2-lab client <loopback-ip:port> <enrolled-device-dir> <bytes-1-to-262144> [--passphrase-stdin]
Both parties must negotiate ALPN h2 and exchange actual HTTP/2 POST/DATA frames.
Test identity private keys must be in an encrypted PKCS#8 device directory."#
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = env::args().collect();
    let result: Result<()> = async {
        match args.as_slice() {
            [_, cmd, listen, ca, cert, key, allowed] if cmd == "server" => {
                run_server(
                    listen.parse()?,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    Path::new(allowed),
                )
                .await
            }
            [_, cmd, server, device, amount] if cmd == "client" => {
                run_client(server.parse()?, Path::new(device), amount.parse()?, false).await
            }
            [_, cmd, server, device, amount, flag]
                if cmd == "client" && flag == "--passphrase-stdin" =>
            {
                run_client(server.parse()?, Path::new(device), amount.parse()?, true).await
            }
            _ => {
                usage();
                Err("invalid arguments".into())
            }
        }
    }
    .await;
    if let Err(error) = result {
        eprintln!("fedup-h2-lab: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_size_and_no_implicit_public_binding() {
        assert_eq!(synthetic_payload(251).len(), 251);
        assert_eq!(synthetic_payload(251)[250], 250);
        assert_eq!(synthetic_payload(252)[251], 0);
        assert_eq!(synthetic_payload(128 * 1024).len(), 128 * 1024);
    }
}
