//! FedUp Linux IP-packet lab: one private pair of TUN endpoints over mutual TLS.
//! Intentionally NOT an Internet VPN, not an HTTPS impersonator, and not production-ready.
//! This version forwards only packets between the fixed client and server,
//! or a single synthetic egress host, inside operator-controlled network namespaces.

use bytes::Bytes;
use fedup_core::{Direction, InternetV4Policy, IpPolicy, LAB_MTU};
use fedup_identity::{decrypt_pkcs8, device_connection, read_password};
use fedup_protocol::{encode_header, parse_header, Frame, FrameKind, HEADER_LEN};
use h2::{client as h2_client, server as h2_server, RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::future::poll_fn;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{interval, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tun::Tun;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_TIMEOUT: Duration = Duration::from_secs(45);
const RECHECK: Duration = Duration::from_secs(5);
const MAX_PACKET: usize = LAB_MTU;
const TUN_BUFFER: usize = 65536;
const MAX_ALLOWLIST_BYTES: u64 = 65536;
const STREAM: u32 = 1;
// A stalled unauthenticated TLS handshake must not monopolize the listener.
const MAX_PENDING_HANDSHAKES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerMode {
    LabRaw,
    LabH2,
    InternetV4H2,
}

impl ServerMode {
    fn http2(self) -> bool {
        self != Self::LabRaw
    }

    fn internet_v4(self) -> bool {
        self == Self::InternetV4H2
    }
}

fn ca_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let chain = rustls_pemfile::certs(&mut reader).collect::<std::io::Result<Vec<_>>>()?;
    if chain.is_empty() {
        return Err("empty certificate chain".into());
    }
    Ok(chain)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::private_key(&mut reader)?.ok_or("missing server private key")?)
}

fn roots(path: &Path) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in ca_certs(path)? {
        store.add(cert)?;
    }
    Ok(store)
}

fn fingerprint(cert: &[u8]) -> String {
    Sha256::digest(cert)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// Fail closed on any missing, oversized or malformed device authorization file.
fn authorized_allowlist(path: &Path, fp: &str) -> Result<bool> {
    if fs::metadata(path)?.len() > MAX_ALLOWLIST_BYTES {
        return Err("device allowlist too large".into());
    }
    let content = fs::read_to_string(path)?;
    if content.len() as u64 > MAX_ALLOWLIST_BYTES {
        return Err("device allowlist too large".into());
    }
    let mut found = false;
    for row in content.lines() {
        let line = row.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 64 || !line.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("malformed device allowlist".into());
        }
        if line.eq_ignore_ascii_case(fp) {
            found = true;
        }
    }
    Ok(found)
}

#[derive(Clone)]
enum DeviceAuthorization {
    Allowlist(PathBuf),
    AccountDatabase(PathBuf),
}

fn authorized(policy: &DeviceAuthorization, fp: &str) -> Result<bool> {
    match policy {
        DeviceAuthorization::Allowlist(path) => authorized_allowlist(path, fp),
        DeviceAuthorization::AccountDatabase(dir) => Ok(fedup_users::authorized_device(dir, fp)?),
    }
}

/// Extra laboratory safeguard: refuse to start in the initial network
/// namespace of the current Linux instance. This does not replace a
/// sandbox or a privilege separation policy.
fn require_isolated_network_namespace() -> Result<()> {
    let current = fs::read_link("/proc/self/ns/net")?;
    let init = fs::read_link("/proc/1/ns/net")?;
    if current == init {
        return Err(
            "experimental IP TUN may only run inside a separate Linux network namespace".into(),
        );
    }
    Ok(())
}

fn private_lab_ip(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(_) => false,
    }
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    timeout(FRAME_TIMEOUT, r.read_exact(&mut header)).await??;
    let parsed = parse_header(&header)?;
    if parsed.payload_len > MAX_PACKET {
        return Err("IP datagram exceeds TUN MTU".into());
    }
    let mut payload = vec![0; parsed.payload_len];
    timeout(FRAME_TIMEOUT, r.read_exact(&mut payload)).await??;
    Ok(Frame::new(parsed.kind, parsed.stream_id, payload)?)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    let header = encode_header(frame)?;
    timeout(IO_TIMEOUT, w.write_all(&header)).await??;
    timeout(IO_TIMEOUT, w.write_all(&frame.payload)).await??;
    timeout(IO_TIMEOUT, w.flush()).await??;
    Ok(())
}

async fn open<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    write_frame(w, &Frame::new(FrameKind::Open, STREAM, Vec::new())?).await
}

fn expect_open(frame: Frame) -> Result<()> {
    if frame.kind != FrameKind::Open || frame.stream_id != STREAM || !frame.payload.is_empty() {
        return Err("invalid TUN session negotiation".into());
    }
    Ok(())
}

fn create_tun(name: &str) -> Result<Arc<Tun>> {
    if name.len() < 3
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err("TUN interface name must be 3-15 ASCII alphanumerics, _ or -".into());
    }
    let tun = Tun::builder()
        .name(name)
        .mtu(MAX_PACKET as i32)
        .up()
        .build()?
        .pop()
        .ok_or("failed to allocate TUN")?;
    println!("created ephemeral TUN {name}, MTU {MAX_PACKET}; addresses/routes are NOT configured");
    Ok(Arc::new(tun))
}

/// Single experimental IP tunnel. No public egress.
/// Only a fixed client/server pair and one synthetic remote host are allowed.
async fn forward<T>(
    stream: T,
    tun: Arc<Tun>,
    is_client: bool,
    revocation: Option<(DeviceAuthorization, String)>,
    internet_v4: bool,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let out_dir = if is_client {
        Direction::ClientToServer
    } else {
        Direction::ServerToClient
    };
    let in_dir = if is_client {
        Direction::ServerToClient
    } else {
        Direction::ClientToServer
    };
    let (mut incoming, mut outgoing) = tokio::io::split(stream);
    // Same Rust admission for client/server. Internet access does not permit
    // spoofing the phone's source or contacting private VPS management networks.
    let lab_policy = IpPolicy::isolated_lab();
    let internet_policy = InternetV4Policy;
    let admits = |packet: &[u8], direction| {
        if internet_v4 {
            internet_policy.admits(packet, direction)
        } else {
            lab_policy.admits(packet, direction)
        }
    };
    let rx_tun = tun.clone();
    let tx_tun = tun;
    let send = async {
        let mut packet = vec![0u8; TUN_BUFFER];
        loop {
            let n = rx_tun.recv(&mut packet).await?;
            if !admits(&packet[..n], out_dir) {
                continue;
            }
            let frame = Frame::new(FrameKind::Datagram, STREAM, packet[..n].to_vec())?;
            write_frame(&mut outgoing, &frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    let receive = async {
        loop {
            let frame = read_frame(&mut incoming).await?;
            if frame.kind != FrameKind::Datagram || frame.stream_id != STREAM {
                return Err("unexpected frame in active IP tunnel".into());
            }
            if !admits(&frame.payload, in_dir) {
                return Err("invalid or spoofed IP packet from peer".into());
            }
            tx_tun.send_all(&frame.payload).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    tokio::pin!(send);
    tokio::pin!(receive);
    let mut periodic = interval(RECHECK);
    loop {
        tokio::select! {
            res = &mut send => return res,
            res = &mut receive => return res,
            _ = periodic.tick() => {
                if let Some((path, fp)) = &revocation {
                    if !authorized(path, fp)? {
                        return Err("TUN device identity revoked".into());
                    }
                }
            }
        }
    }
}

const H2_URI: &str = "/fedup-lab/v1/ip-tunnel";
const H2_TYPE: &str = "application/vnd.fedup.ip-packets";
const H2_CHUNK: usize = 8192;

/// Stream adapter with bounded HTTP/2 flow control. DATA frames may split or
/// combine FedUp framing; the duplex stream reconstitutes the byte stream.
/// This is genuine HTTP/2 framing, not a forged ALPN value.
async fn send_h2(send: &mut SendStream<Bytes>, mut buffer: Bytes) -> Result<()> {
    while !buffer.is_empty() {
        let requested = buffer.len().min(H2_CHUNK);
        send.reserve_capacity(requested);
        let available = timeout(FRAME_TIMEOUT, poll_fn(|cx| send.poll_capacity(cx)))
            .await?
            .ok_or("HTTP/2 stream closed before send capacity became available")??;
        if available == 0 {
            return Err("HTTP/2 send window unavailable".into());
        }
        send.send_data(buffer.split_to(available.min(requested)), false)?;
    }
    Ok(())
}

async fn h2_bridge(
    mut receive: RecvStream,
    mut send: SendStream<Bytes>,
    socket: DuplexStream,
) -> Result<()> {
    let (mut read_pipe, mut write_pipe) = tokio::io::split(socket);
    let outbound = async {
        let mut buf = [0u8; H2_CHUNK];
        loop {
            let n = read_pipe.read(&mut buf).await?;
            if n == 0 {
                send.send_data(Bytes::new(), true)?;
                return Ok::<(), Box<dyn Error + Send + Sync>>(());
            }
            send_h2(&mut send, Bytes::copy_from_slice(&buf[..n])).await?;
        }
    };
    let inbound = async {
        while let Some(frame) = timeout(FRAME_TIMEOUT, receive.data()).await? {
            let bytes = frame?;
            write_pipe.write_all(&bytes).await?;
            receive.flow_control().release_capacity(bytes.len())?;
        }
        write_pipe.shutdown().await?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    tokio::try_join!(inbound, outbound)?;
    Ok(())
}

fn is_h2_request(request: &Request<RecvStream>) -> bool {
    request.method() == http::Method::POST
        && request.uri().path() == H2_URI
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|value| value == H2_TYPE)
}

async fn h2_server_session(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    tun: Arc<Tun>,
    revocation: (DeviceAuthorization, String),
    internet_v4: bool,
    active_session: Arc<Semaphore>,
) -> Result<()> {
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("ALPN h2 required for HTTP/2 TUN".into());
    }
    let mut connection = timeout(IO_TIMEOUT, h2_server::handshake(tls)).await??;
    let (request, mut respond) = timeout(IO_TIMEOUT, connection.accept())
        .await?
        .ok_or("HTTP/2 client did not open tunnel request")??;
    // A real HTTP/2 request allowed only AFTER mTLS chain verification
    // and the server's per-device certificate fingerprint authorization.
    // This path never creates a new TUN or forwards any packet. Android
    // can validate its full offline enrollment chain without routing traffic.
    if request.method() == http::Method::GET && request.uri().path() == "/fedup-lab/v1/auth-check" {
        respond.send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header(http::header::CACHE_CONTROL, "no-store")
                .body(())?,
            true,
        )?;
        // h2 queues HEADERS. Drive its connection state machine before
        // closing TLS, otherwise the client sees a reset instead of 204.
        connection.graceful_shutdown();
        let _ = timeout(Duration::from_secs(2), connection.accept()).await;
        return Ok(());
    }
    if !is_h2_request(&request) {
        respond.send_response(
            Response::builder().status(StatusCode::NOT_FOUND).body(())?,
            true,
        )?;
        return Err("HTTP/2 request was not the authorized fixed IP tunnel".into());
    }
    // Only one peer may read/write the single shared TUN. Authentication
    // probes can still run concurrently; actual packet sessions cannot.
    let _active = match active_session.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            respond.send_response(
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(())?,
                true,
            )?;
            connection.graceful_shutdown();
            let _ = timeout(Duration::from_secs(2), connection.accept()).await;
            return Err("another IP session is already using the TUN".into());
        }
    };
    let outgoing = respond.send_response(
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, H2_TYPE)
            .body(())?,
        false,
    )?;

    let (tun_end, bridge_end) = duplex(64 * 1024);
    let bridge = tokio::spawn(h2_bridge(request.into_body(), outgoing, bridge_end));
    // Drive the HTTP/2 connection state machine for the lifetime of its
    // active stream. Refuse any additional stream on this one-client lab.
    let driver = tokio::spawn(async move {
        while let Some(next) = connection.accept().await {
            let (_, mut respond) = next?;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(())?,
                true,
            )?;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });
    let result = forward(tun_end, tun, false, Some(revocation), internet_v4).await;
    driver.abort();
    bridge.abort();
    result
}

async fn h2_client_session(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    hostname: &str,
    tun_name: &str,
    internet_v4: bool,
) -> Result<()> {
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("ALPN h2 not negotiated".into());
    }
    let (mut sender, connection) = timeout(IO_TIMEOUT, h2_client::handshake(tls)).await??;
    let driver = tokio::spawn(connection);
    sender = timeout(IO_TIMEOUT, sender.ready()).await??;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{hostname}{H2_URI}"))
        .header(http::header::CONTENT_TYPE, H2_TYPE)
        .body(())?;
    let (reply, outgoing) = sender.send_request(request, false)?;
    let response = timeout(IO_TIMEOUT, reply).await??;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_none_or(|h| h != H2_TYPE)
    {
        return Err("HTTP/2 tunnel request rejected by server".into());
    }
    let (tun_end, bridge_end) = duplex(64 * 1024);
    let bridge = tokio::spawn(h2_bridge(response.into_body(), outgoing, bridge_end));
    // Only create TUN after TLS verification and HTTP/2 authorization.
    let tun = create_tun(tun_name)?;
    println!("FedUp genuine HTTP/2 IP tunnel authenticated; no host routing was changed");
    let result = forward(tun_end, tun, true, None, internet_v4).await;
    bridge.abort();
    driver.abort();
    result
}

/// Authorization-only HTTP/2 request: no TUN is created, and only a
/// fingerprint-authorized device receives 204 from the server.
async fn h2_auth_probe(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    hostname: &str,
) -> Result<()> {
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("authorization probe requires ALPN h2".into());
    }
    let (mut sender, connection) = timeout(IO_TIMEOUT, h2_client::handshake(tls)).await??;
    let driver = tokio::spawn(connection);
    sender = timeout(IO_TIMEOUT, sender.ready()).await??;
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{hostname}/fedup-lab/v1/auth-check"))
        .body(())?;
    let (response, _) = sender.send_request(request, true)?;
    let reply = timeout(IO_TIMEOUT, response).await??;
    driver.abort();
    if reply.status() != StatusCode::NO_CONTENT {
        return Err(format!("device not authorized by server: {}", reply.status()).into());
    }
    println!("FedUp mTLS and real HTTP/2 authorization probe: PASS (no TUN created)");
    Ok(())
}

async fn server_session(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    tun: Arc<Tun>,
    authorization: &DeviceAuthorization,
    mode: ServerMode,
    active_session: Arc<Semaphore>,
    handshake_slot: OwnedSemaphorePermit,
) -> Result<()> {
    let mut tls = timeout(IO_TIMEOUT, acceptor.accept(socket)).await??;
    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("missing mTLS device certificate")?;
    let fp = fingerprint(peer.as_ref());
    if !authorized(authorization, &fp)? {
        return Err("device not authorized".into());
    }
    // Do not keep a scarce handshake slot for a potentially long-lived TUN.
    drop(handshake_slot);
    if mode.http2() {
        return h2_server_session(
            tls,
            tun,
            (authorization.clone(), fp),
            mode.internet_v4(),
            active_session,
        )
        .await;
    }
    let _active = active_session
        .try_acquire_owned()
        .map_err(|_| "another IP session is already using the TUN")?;
    let req = read_frame(&mut tls).await?;
    expect_open(req)?;
    open(&mut tls).await?;
    forward(tls, tun, false, Some((authorization.clone(), fp)), false).await
}

async fn server(
    listen: SocketAddr,
    name: &str,
    ca: &Path,
    certificate: &Path,
    key: &Path,
    authorization: DeviceAuthorization,
    mode: ServerMode,
) -> Result<()> {
    if mode.internet_v4() {
        // This opt-in mode is intended for a fresh operator-controlled VPS.
        // Server never modifies host routes, sysctls or firewalls; the
        // independent, explicitly invoked egress setup is responsible.
        if !listen.is_ipv4() {
            return Err("VPS IPv4 server needs an IPv4 listener".into());
        }
    } else {
        require_isolated_network_namespace()?;
        if !private_lab_ip(listen) {
            return Err("lab server must bind loopback or private IPv4 address".into());
        }
    }
    if listen.is_ipv6() {
        return Err("IPv6 outer transport not configured in this lab".into());
    }
    match &authorization {
        DeviceAuthorization::Allowlist(path) => {
            let _ = authorized_allowlist(path, "")?;
        }
        DeviceAuthorization::AccountDatabase(dir) => {
            // Validate account DB presence/permissions before accepting a socket.
            let _ = fedup_users::authenticate(dir, "startup-probe", b"not-a-valid-password")?;
        }
    }
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(ca)?)).build()?,
        )
        .with_single_cert(ca_certs(certificate)?, load_key(key)?)?;
    if mode.http2() {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tun = create_tun(name)?;
    let listener = TcpListener::bind(listen).await?;
    // Bound work before authentication; an incomplete ClientHello now stalls
    // only its own task, not all subsequent incoming TCP connections.
    let pending_handshakes = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let active_session = Arc::new(Semaphore::new(1));
    println!(
        "FedUp {} server listening on {listen}; one active IP tunnel",
        if mode.internet_v4() {
            "experimental VPS IPv4"
        } else {
            "isolated lab"
        }
    );
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(slot) = pending_handshakes.clone().try_acquire_owned() else {
            // Fail closed under unauthenticated load. Do not queue unbounded
            // TCP connections or allow one slow client to block everyone.
            drop(socket);
            continue;
        };
        let acceptor = acceptor.clone();
        let tun = tun.clone();
        let authorization = authorization.clone();
        let active_session = active_session.clone();
        tokio::spawn(async move {
            if let Err(error) = server_session(
                socket,
                acceptor,
                tun,
                &authorization,
                mode,
                active_session,
                slot,
            )
            .await
            {
                eprintln!("IP session closed: {error}");
            }
        });
    }
}

async fn client(
    server: SocketAddr,
    name: &str,
    directory: &Path,
    password_stdin: bool,
    http2: bool,
    auth_only: bool,
    internet_v4: bool,
) -> Result<()> {
    require_isolated_network_namespace()?;
    if !private_lab_ip(server) {
        return Err("lab client accepts only private IPv4 or loopback server address".into());
    }
    let device = device_connection(directory)?;
    let passphrase = read_password(false, password_stdin)?;
    let decoded = decrypt_pkcs8(&device.encrypted_key_path, passphrase.as_bytes())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decoded.to_vec()));
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(&device.ca_path)?)
        .with_client_auth_cert(ca_certs(&device.cert_path)?, key)?;
    if http2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    let connector = TlsConnector::from(Arc::new(config));
    let socket = timeout(IO_TIMEOUT, TcpStream::connect(server)).await??;
    let hostname = device.server_name;
    let server_name: ServerName<'static> = ServerName::try_from(hostname.clone())?;
    let mut tls = timeout(IO_TIMEOUT, connector.connect(server_name, socket)).await??;
    if auth_only {
        if !http2 {
            return Err("authorization probe needs real HTTP/2".into());
        }
        return h2_auth_probe(tls, &hostname).await;
    }
    if http2 {
        return h2_client_session(tls, &hostname, name, internet_v4).await;
    }
    open(&mut tls).await?;
    expect_open(read_frame(&mut tls).await?)?;
    // TUN only after successful authentication; a network outage cannot
    // silently bypass the tunnel (but OS routing must be managed separately).
    let tun = create_tun(name)?;
    println!("FedUp IP lab authenticated and ready; configure addresses inside namespace");
    forward(tls, tun, true, None, false).await
}

fn usage() {
    eprintln!(
        r#"FedUp IP lab — NOT a production VPN. Experimental genuine HTTPS/2 mode:
fedup-tun server <private-listen-ip:port> <tun-name> <ca.pem> <server.pem> <server.key> <allowlist.txt>
fedup-tun client <private-server-ip:port> <tun-name> <enrolled-device-dir> [--passphrase-stdin]
fedup-tun server-h2 <private-listen-ip:port> <tun-name> <ca.pem> <server.pem> <server.key> <allowlist.txt>
fedup-tun server-h2-accounts <private-listen-ip:port> <tun-name> <ca.pem> <server.pem> <server.key> <users-dir>
fedup-tun server-vps-v4 <listen-ip:port> <tun-name> <ca.pem> <server.pem> <server.key> <users-dir> --unsafe-experimental-public-egress
fedup-tun client-h2 <private-server-ip:port> <tun-name> <enrolled-device-dir> [--passphrase-stdin]
fedup-tun probe-h2 <private-server-ip:port> <enrolled-device-dir> [--passphrase-stdin]
fedup-tun client-vps-v4 <private-test-server-ip:port> <tun-name> <device-dir> [--passphrase-stdin]

Fixed peers: 10.77.0.2 <-> 10.77.0.1 or 10.88.0.10, and
fd42:fed0::2 <-> fd42:fed0::1 or fd42:fed1::10.
Lab modes: no Internet egress, use only isolated Linux network namespaces.
VPS-v4: separate experimental opt-in, IPv4 only, ONE device, never installs NAT,
addresses, DNS or firewall itself. Administrator must configure explicit egress
rules, and IPv6 remains unsupported. Not a production VPN or leak-proof client."#
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = env::args().collect();
    let result: Result<()> = async {
        match args.as_slice() {
            [_, cmd, bind, tun, ca, cert, key, allow] if cmd == "server" || cmd == "server-h2" => {
                server(
                    bind.parse()?,
                    tun,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    DeviceAuthorization::Allowlist(PathBuf::from(allow)),
                    if cmd == "server-h2" {
                        ServerMode::LabH2
                    } else {
                        ServerMode::LabRaw
                    },
                )
                .await
            }
            [_, cmd, bind, tun, ca, cert, key, users] if cmd == "server-h2-accounts" => {
                server(
                    bind.parse()?,
                    tun,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    DeviceAuthorization::AccountDatabase(PathBuf::from(users)),
                    ServerMode::LabH2,
                )
                .await
            }
            [_, cmd, bind, tun, ca, cert, key, users, flag]
                if cmd == "server-vps-v4" && flag == "--unsafe-experimental-public-egress" =>
            {
                server(
                    bind.parse()?,
                    tun,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    DeviceAuthorization::AccountDatabase(PathBuf::from(users)),
                    ServerMode::InternetV4H2,
                )
                .await
            }
            [_, cmd, addr, tun, device] if cmd == "client-vps-v4" => {
                client(
                    addr.parse()?,
                    tun,
                    Path::new(device),
                    false,
                    true,
                    false,
                    true,
                )
                .await
            }
            [_, cmd, addr, tun, device, flag]
                if cmd == "client-vps-v4" && flag == "--passphrase-stdin" =>
            {
                client(
                    addr.parse()?,
                    tun,
                    Path::new(device),
                    true,
                    true,
                    false,
                    true,
                )
                .await
            }
            [_, cmd, addr, tun, device] if cmd == "client" || cmd == "client-h2" => {
                client(
                    addr.parse()?,
                    tun,
                    Path::new(device),
                    false,
                    cmd == "client-h2",
                    false,
                    false,
                )
                .await
            }
            [_, cmd, addr, tun, device, flag]
                if (cmd == "client" || cmd == "client-h2") && flag == "--passphrase-stdin" =>
            {
                client(
                    addr.parse()?,
                    tun,
                    Path::new(device),
                    true,
                    cmd == "client-h2",
                    false,
                    false,
                )
                .await
            }
            [_, cmd, addr, device] if cmd == "probe-h2" => {
                client(
                    addr.parse()?,
                    "",
                    Path::new(device),
                    false,
                    true,
                    true,
                    false,
                )
                .await
            }
            [_, cmd, addr, device, flag] if cmd == "probe-h2" && flag == "--passphrase-stdin" => {
                client(
                    addr.parse()?,
                    "",
                    Path::new(device),
                    true,
                    true,
                    true,
                    false,
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
    if let Err(err) = result {
        eprintln!("fedup-tun: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_tun_mtu_agrees_with_portable_acl() {
        assert_eq!(MAX_PACKET, IpPolicy::isolated_lab().mtu());
    }

    #[test]
    fn rejects_unexpected_open_frames() {
        let wrong = Frame::new(FrameKind::Datagram, 1, vec![]).unwrap();
        assert!(expect_open(wrong).is_err());
    }
}
