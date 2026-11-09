//! FedUp Linux IP-packet lab: one private pair of TUN endpoints over mutual TLS.
//! Intentionally NOT an Internet VPN, not an HTTPS impersonator, and not production-ready.
//! This version forwards only packets 10.77.0.2 <-> 10.77.0.1 (and optional IPv6
//! fd42:fed0::2 <-> fd42:fed0::1) inside an operator-controlled network namespace.

use fedup_identity::{decrypt_pkcs8, device_connection, read_password};
use fedup_protocol::{encode_header, parse_header, Frame, FrameKind, HEADER_LEN};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{interval, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tun::Tun;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_TIMEOUT: Duration = Duration::from_secs(45);
const RECHECK: Duration = Duration::from_secs(5);
const MAX_PACKET: usize = 1280;
const TUN_BUFFER: usize = 65536;
const MAX_ALLOWLIST_BYTES: u64 = 65536;
const STREAM: u32 = 1;

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
fn authorized(path: &Path, fp: &str) -> Result<bool> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Extra laboratory safeguard: refuse to start in the initial network
/// namespace of the current Linux instance. This does not replace a
/// sandbox or a privilege separation policy.
fn require_isolated_network_namespace() -> Result<()> {
    let current = fs::read_link("/proc/self/ns/net")?;
    let init = fs::read_link("/proc/1/ns/net")?;
    if current == init {
        return Err("experimental IP TUN may only run inside a separate Linux network namespace".into());
    }
    Ok(())
}

fn private_lab_ip(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(_) => false,
    }
}

fn addresses(dir: Direction) -> (IpAddr, IpAddr) {
    match dir {
        Direction::ClientToServer => (
            IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
        ),
        Direction::ServerToClient => (
            IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
        ),
    }
}

fn addresses_v6(dir: Direction) -> (Ipv6Addr, Ipv6Addr) {
    let server: Ipv6Addr = "fd42:fed0::1".parse().expect("static IPv6");
    let client: Ipv6Addr = "fd42:fed0::2".parse().expect("static IPv6");
    match dir {
        Direction::ClientToServer => (client, server),
        Direction::ServerToClient => (server, client),
    }
}

/// Reject untrusted traffic that could inject/escape outside the lab pair.
/// Validity here means *framing, IP length and peer addresses*, not full
/// checksums or protocol correctness: kernel verifies those after TUN injection.
fn valid_ip(packet: &[u8], dir: Direction) -> bool {
    if packet.len() < 20 || packet.len() > MAX_PACKET {
        return false;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let header = ((packet[0] & 15) as usize) * 4;
            if header < 20 || header > packet.len() {
                return false;
            }
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total != packet.len() {
                return false;
            }
            // Disallow fragmentation until fragment state accounting is defined.
            let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
            if flags_frag & 0x3fff != 0 {
                return false;
            }
            let src = IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let dst = IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            let expected = addresses(dir);
            src == expected.0 && dst == expected.1
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            let payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if payload + 40 != packet.len() {
                return false;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("length checked"));
            let dst =
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("length checked"));
            (src, dst) == addresses_v6(dir)
        }
        _ => false,
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

/// Single VPN session. The TUN is NOT connected to any public egress.
/// Only a fixed pair of /32 and /128 addresses is allowed.
async fn forward<T>(
    stream: T,
    tun: Arc<Tun>,
    is_client: bool,
    revocation: Option<(PathBuf, String)>,
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
    let rx_tun = tun.clone();
    let tx_tun = tun;
    let send = async {
        let mut packet = vec![0u8; TUN_BUFFER];
        loop {
            let n = rx_tun.recv(&mut packet).await?;
            if !valid_ip(&packet[..n], out_dir) {
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
            if !valid_ip(&frame.payload, in_dir) {
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

async fn server_session(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    tun: Arc<Tun>,
    allowlist: &Path,
) -> Result<()> {
    let mut tls = timeout(IO_TIMEOUT, acceptor.accept(socket)).await??;
    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("missing mTLS device certificate")?;
    let fp = fingerprint(peer.as_ref());
    if !authorized(allowlist, &fp)? {
        return Err("device not authorized".into());
    }
    let req = read_frame(&mut tls).await?;
    expect_open(req)?;
    open(&mut tls).await?;
    forward(tls, tun, false, Some((allowlist.to_path_buf(), fp))).await
}

async fn server(
    listen: SocketAddr,
    name: &str,
    ca: &Path,
    certificate: &Path,
    key: &Path,
    allowlist: &Path,
) -> Result<()> {
    require_isolated_network_namespace()?;
    if !private_lab_ip(listen) {
        return Err("lab server must bind loopback or private IPv4 address".into());
    }
    if listen.is_ipv6() {
        return Err("IPv6 outer transport not configured in this lab".into());
    }
    let _ = authorized(allowlist, "")?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(ca)?)).build()?,
        )
        .with_single_cert(ca_certs(certificate)?, load_key(key)?)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tun = create_tun(name)?;
    let listener = TcpListener::bind(listen).await?;
    println!("FedUp IP lab server listening on {listen}; one device at a time");
    loop {
        let (socket, _) = listener.accept().await?;
        if let Err(error) = server_session(socket, acceptor.clone(), tun.clone(), allowlist).await {
            eprintln!("IP session closed: {error}");
        }
    }
}

async fn client(
    server: SocketAddr,
    name: &str,
    directory: &Path,
    password_stdin: bool,
) -> Result<()> {
    require_isolated_network_namespace()?;
    if !private_lab_ip(server) {
        return Err("lab client accepts only private IPv4 or loopback server address".into());
    }
    let device = device_connection(directory)?;
    let passphrase = read_password(false, password_stdin)?;
    let decoded = decrypt_pkcs8(&device.encrypted_key_path, passphrase.as_bytes())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decoded.to_vec()));
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(&device.ca_path)?)
        .with_client_auth_cert(ca_certs(&device.cert_path)?, key)?;
    let connector = TlsConnector::from(Arc::new(config));
    let socket = timeout(IO_TIMEOUT, TcpStream::connect(server)).await??;
    let server_name: ServerName<'static> = ServerName::try_from(device.server_name)?;
    let mut tls = timeout(IO_TIMEOUT, connector.connect(server_name, socket)).await??;
    open(&mut tls).await?;
    expect_open(read_frame(&mut tls).await?)?;
    // TUN only after successful authentication; a network outage cannot
    // silently bypass the tunnel (but OS routing must be managed separately).
    let tun = create_tun(name)?;
    println!("FedUp IP lab authenticated and ready; configure addresses inside namespace");
    forward(tls, tun, true, None).await
}

fn usage() {
    eprintln!(
        r#"FedUp IP lab — NOT a production VPN and NOT HTTPS:
fedup-tun server <private-listen-ip:port> <tun-name> <ca.pem> <server.pem> <server.key> <allowlist.txt>
fedup-tun client <private-server-ip:port> <tun-name> <enrolled-device-dir> [--passphrase-stdin]

Only 10.77.0.2 <-> 10.77.0.1 and fd42:fed0::2 <-> fd42:fed0::1 IP packets
are accepted. No NAT, Internet egress, DNS, full-tunnel routing or kill switch.
Use only in controlled, separate Linux network namespaces."#
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = env::args().collect();
    let result: Result<()> = async {
        match args.as_slice() {
            [_, cmd, bind, tun, ca, cert, key, allow] if cmd == "server" => {
                server(
                    bind.parse()?,
                    tun,
                    Path::new(ca),
                    Path::new(cert),
                    Path::new(key),
                    Path::new(allow),
                )
                .await
            }
            [_, cmd, addr, tun, device] if cmd == "client" => {
                client(addr.parse()?, tun, Path::new(device), false).await
            }
            [_, cmd, addr, tun, device, flag]
                if cmd == "client" && flag == "--passphrase-stdin" =>
            {
                client(addr.parse()?, tun, Path::new(device), true).await
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
    fn ipv4_packet(source: [u8; 4], dest: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(28u16).to_be_bytes());
        p[8] = 64;
        p[9] = 1;
        p[12..16].copy_from_slice(&source);
        p[16..20].copy_from_slice(&dest);
        p
    }
    fn ipv6_packet(source: Ipv6Addr, dest: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(8u16).to_be_bytes());
        p[6] = 58;
        p[7] = 64;
        p[8..24].copy_from_slice(&source.octets());
        p[24..40].copy_from_slice(&dest.octets());
        p
    }

    #[test]
    fn ipv4_valid_lengths_and_directions() {
        let mut pkt = ipv4_packet([10, 77, 0, 2], [10, 77, 0, 1]);
        assert!(valid_ip(&pkt, Direction::ClientToServer));
        assert!(!valid_ip(&pkt, Direction::ServerToClient));
        pkt[2] = 0;
        pkt[3] = 27;
        assert!(!valid_ip(&pkt, Direction::ClientToServer));
        pkt[2] = 0;
        pkt[3] = 28;
        pkt[6] = 0x20; // disallowed fragmented source
        assert!(!valid_ip(&pkt, Direction::ClientToServer));
    }

    #[test]
    fn blocks_ip_spoofing_unknown_version_and_oversized_packets() {
        let bad = ipv4_packet([198, 51, 100, 1], [10, 77, 0, 1]);
        assert!(!valid_ip(&bad, Direction::ClientToServer));
        let mut wrong = ipv4_packet([10, 77, 0, 2], [10, 77, 0, 1]);
        wrong[0] = 0x75;
        assert!(!valid_ip(&wrong, Direction::ClientToServer));
        assert!(!valid_ip(
            &vec![0u8; MAX_PACKET + 1],
            Direction::ClientToServer
        ));
    }

    #[test]
    fn ipv6_pairs_and_lengths() {
        let (src, dst) = addresses_v6(Direction::ClientToServer);
        let mut packet = ipv6_packet(src, dst);
        assert!(valid_ip(&packet, Direction::ClientToServer));
        assert!(!valid_ip(&packet, Direction::ServerToClient));
        packet[4] = 0;
        packet[5] = 7;
        assert!(!valid_ip(&packet, Direction::ClientToServer));
    }

    #[test]
    fn rejects_unexpected_open_frames() {
        let bad = Frame::new(FrameKind::Datagram, 1, vec![]).unwrap();
        assert!(expect_open(bad).is_err());
    }
}
