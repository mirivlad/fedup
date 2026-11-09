//! Experimental mTLS TCP link to one operator-configured destination.
//! NOT a general-purpose VPN, HTTPS service, or DPI evasion system.
use fedup_identity::{decrypt_pkcs8, read_password};
use fedup_protocol::{encode_header, parse_header, Frame, FrameKind, HEADER_LEN};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{interval, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type LinkResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const FRAME_TIMEOUT: Duration = Duration::from_secs(300);
const RECHECK_INTERVAL: Duration = Duration::from_secs(5);
const MAX_SESSIONS: usize = 16;
const MAX_CHUNK: usize = 16 * 1024;
const STREAM_ID: u32 = 1;
const MAX_ALLOWLIST_BYTES: u64 = 64 * 1024;

fn certs(path: &Path) -> LinkResult<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err("empty certificate chain".into());
    }
    Ok(certificates)
}

fn private_key(path: &Path) -> LinkResult<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::private_key(&mut reader)?.ok_or("private key not found")?)
}

fn encrypted_client_key(path: &Path, password_stdin: bool) -> LinkResult<PrivateKeyDer<'static>> {
    let password = read_password(false, password_stdin)?;
    let decoded = decrypt_pkcs8(path, password.as_bytes())?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        decoded.to_vec(),
    )))
}

fn trust_roots(path: &Path) -> LinkResult<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certs(path)? {
        roots.add(certificate)?;
    }
    Ok(roots)
}

fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn authorized(path: &Path, fingerprint: &str) -> LinkResult<bool> {
    if fs::metadata(path)?.len() > MAX_ALLOWLIST_BYTES {
        return Err("client authorization list is too large".into());
    }
    let text = fs::read_to_string(path)?;
    let mut found = false;
    for line in text.lines() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid client authorization list".into());
        }
        if value.eq_ignore_ascii_case(fingerprint) {
            found = true;
        }
    }
    Ok(found)
}

async fn read_frame_async<R: AsyncRead + Unpin>(reader: &mut R) -> LinkResult<Frame> {
    let mut bytes = [0_u8; HEADER_LEN];
    timeout(FRAME_TIMEOUT, reader.read_exact(&mut bytes)).await??;
    let header = parse_header(&bytes)?;
    let mut payload = vec![0_u8; header.payload_len];
    timeout(FRAME_TIMEOUT, reader.read_exact(&mut payload)).await??;
    Ok(Frame::new(header.kind, header.stream_id, payload)?)
}

async fn send_frame_async<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> LinkResult<()> {
    let header = encode_header(frame)?;
    timeout(CONNECT_TIMEOUT, writer.write_all(&header)).await??;
    timeout(CONNECT_TIMEOUT, writer.write_all(&frame.payload)).await??;
    timeout(CONNECT_TIMEOUT, writer.flush()).await??;
    Ok(())
}

async fn send_kind<W: AsyncWrite + Unpin>(writer: &mut W, kind: FrameKind) -> LinkResult<()> {
    send_frame_async(writer, &Frame::new(kind, STREAM_ID, Vec::new())?).await
}

async fn outbound<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut src: R,
    mut dest: W,
) -> LinkResult<()> {
    let mut buffer = [0_u8; MAX_CHUNK];
    loop {
        let count = src.read(&mut buffer).await?;
        if count == 0 {
            send_kind(&mut dest, FrameKind::Close).await?;
            return Ok(());
        }
        let frame = Frame::new(FrameKind::Data, STREAM_ID, buffer[..count].to_vec())?;
        send_frame_async(&mut dest, &frame).await?;
    }
}

async fn inbound<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut src: R,
    mut dest: W,
) -> LinkResult<()> {
    loop {
        let frame = read_frame_async(&mut src).await?;
        if frame.stream_id != STREAM_ID {
            return Err("unexpected stream identifier".into());
        }
        match frame.kind {
            FrameKind::Data => dest.write_all(&frame.payload).await?,
            FrameKind::Close if frame.payload.is_empty() => {
                dest.shutdown().await?;
                return Ok(());
            }
            _ => return Err("unexpected frame in active TCP stream".into()),
        }
    }
}

/// One TCP socket per framed stream. The two directions are independent, and
/// Close is a logical half-close rather than a premature TLS close_notify.
async fn pump<T>(socket: TcpStream, tls: T) -> LinkResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (plain_read, plain_write) = tokio::io::split(socket);
    let (tls_read, tls_write) = tokio::io::split(tls);
    tokio::try_join!(
        outbound(plain_read, tls_write),
        inbound(tls_read, plain_write)
    )?;
    Ok(())
}

async fn server_session(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    target: SocketAddr,
    allowlist: PathBuf,
) -> LinkResult<()> {
    let mut tls = timeout(CONNECT_TIMEOUT, acceptor.accept(socket)).await??;
    let peer_cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("client identity certificate missing")?;
    let id = fingerprint(peer_cert.as_ref());
    if !authorized(&allowlist, &id)? {
        return Err("client certificate is not authorized".into());
    }
    let request = read_frame_async(&mut tls).await?;
    if request.kind != FrameKind::Open
        || request.stream_id != STREAM_ID
        || !request.payload.is_empty()
    {
        return Err("invalid stream opening request".into());
    }

    let target_stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await??;
    send_kind(&mut tls, FrameKind::Open).await?;

    // Re-check a device fingerprint during established sessions. A device
    // removed from the allowlist is disconnected within one recheck period
    // under a functioning runtime and filesystem.
    let transfer = pump(target_stream, tls);
    tokio::pin!(transfer);
    let mut revocation_check = interval(RECHECK_INTERVAL);
    loop {
        tokio::select! {
            result = &mut transfer => return result,
            _ = revocation_check.tick() => {
                if !authorized(&allowlist, &id)? {
                    return Err("active device authorization was revoked".into());
                }
            }
        }
    }
}

async fn server(
    listen: SocketAddr,
    target: SocketAddr,
    ca: &Path,
    cert: &Path,
    key: &Path,
    allowlist: PathBuf,
    allow_public: bool,
) -> LinkResult<()> {
    if !listen.ip().is_loopback() && !allow_public {
        return Err("non-loopback bind requires explicit --allow-public-bind".into());
    }
    if !target.ip().is_loopback() {
        return Err("experimental server requires a loopback-only target".into());
    }
    // Fail closed on malformed/missing authorizations before opening the port.
    let _ = authorized(&allowlist, "")?;
    let verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(trust_roots(ca)?)).build()?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(cert)?, private_key(key)?)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(listen).await?;
    let capacity = Arc::new(Semaphore::new(MAX_SESSIONS));
    println!("FedUp experimental TCP link listening on {listen}; fixed target {target}");
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            // Admission is bounded; never queue unbounded unauthenticated sessions.
            continue;
        };
        let acceptor = acceptor.clone();
        let allowlist = allowlist.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = server_session(socket, acceptor, target, allowlist).await {
                eprintln!("session terminated: {error}");
            }
        });
    }
}

async fn client_session(
    local: TcpStream,
    server: SocketAddr,
    hostname: String,
    connector: TlsConnector,
) -> LinkResult<()> {
    let socket = timeout(CONNECT_TIMEOUT, TcpStream::connect(server)).await??;
    let name: ServerName<'static> = ServerName::try_from(hostname)?;
    let mut tls = timeout(CONNECT_TIMEOUT, connector.connect(name, socket)).await??;
    send_kind(&mut tls, FrameKind::Open).await?;
    let response = read_frame_async(&mut tls).await?;
    if response.kind != FrameKind::Open
        || response.stream_id != STREAM_ID
        || !response.payload.is_empty()
    {
        return Err("remote rejected opening the TCP stream".into());
    }
    pump(local, tls).await
}

async fn client(
    bind: SocketAddr,
    server: SocketAddr,
    hostname: String,
    ca: &Path,
    cert: &Path,
    key: PrivateKeyDer<'static>,
) -> LinkResult<()> {
    if !bind.ip().is_loopback() {
        return Err("experimental client can only bind to loopback".into());
    }
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(trust_roots(ca)?)
        .with_client_auth_cert(certs(cert)?, key)?;
    let connector = TlsConnector::from(Arc::new(config));
    let listener = TcpListener::bind(bind).await?;
    let capacity = Arc::new(Semaphore::new(MAX_SESSIONS));
    println!("FedUp experimental local TCP forwarding: {bind} -> {server}");
    loop {
        let (local, _) = listener.accept().await?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        let connector = connector.clone();
        let hostname = hostname.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = client_session(local, server, hostname, connector).await {
                eprintln!("local connection terminated: {error}");
            }
        });
    }
}

fn usage() {
    eprintln!(
        "EXPERIMENTAL TCP link, NOT a VPN:\n\
         fedup-link server <listen-ip:port> <loopback-target-ip:port> <ca.pem> <server.pem> <server.key> <allowlist.txt> [--allow-public-bind]\n\
         fedup-link client <loopback-listen-ip:port> <server-ip:port> <server-dns-name> <ca.pem> <client.pem> <encrypted-key.pem> --encrypted-key [--passphrase-stdin]\n\
         fedup-link client <...> <plaintext-key.pem> --unsafe-lab-plaintext-key (temporary test compatibility)\n\
         fedup-link fingerprint <client.pem>\n\
         Both sides require operator-controlled certificates; the allowlist contains one SHA-256 certificate fingerprint per line."
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = env::args().collect();
    let result: LinkResult<()> = async {
        match args.as_slice() {
            [_, action, cert] if action == "fingerprint" => {
                println!("{}", fingerprint(certs(Path::new(cert))?[0].as_ref()));
                Ok(())
            }
            [_, action, listen, target, ca, cert, key, allowlist] if action == "server" => {
                server(
                    listen.parse()?,
                    target.parse()?,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    PathBuf::from(allowlist),
                    false,
                )
                .await
            }
            [_, action, listen, target, ca, cert, key, allowlist, flag]
                if action == "server" && flag == "--allow-public-bind" =>
            {
                server(
                    listen.parse()?,
                    target.parse()?,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    PathBuf::from(allowlist),
                    true,
                )
                .await
            }
            [_, action, bind, server_addr, hostname, ca, cert, key, mode @ ..]
                if action == "client" =>
            {
                let client_key = match mode {
                    [encrypted] if encrypted == "--encrypted-key" => {
                        encrypted_client_key(Path::new(key), false)?
                    }
                    [encrypted, stdin_flag]
                        if encrypted == "--encrypted-key" && stdin_flag == "--passphrase-stdin" =>
                    {
                        encrypted_client_key(Path::new(key), true)?
                    }
                    [unsafe_flag] if unsafe_flag == "--unsafe-lab-plaintext-key" => {
                        private_key(Path::new(key))?
                    }
                    _ => {
                        return Err(
                            "specify --encrypted-key or explicit unsafe lab key mode".into()
                        );
                    }
                };
                client(
                    bind.parse()?,
                    server_addr.parse()?,
                    hostname.to_string(),
                    Path::new(ca),
                    Path::new(cert),
                    client_key,
                )
                .await
            }
            _ => {
                usage();
                Err("invalid arguments".into())
            }
        }
    }
    .await;
    if let Err(error) = result {
        eprintln!("FedUp link failed: {error}");
        std::process::exit(1);
    }
}
