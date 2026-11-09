//! One-shot loopback mTLS echo laboratory. Not a tunnel and not production ready.
use fedup_protocol::{read_frame, write_frame, Frame, FrameKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const IO_DEADLINE: Duration = Duration::from_secs(8);
const MAX_PING_BYTES: usize = 64;

type LabResult<T> = Result<T, Box<dyn Error>>;

fn load_certs(path: &Path) -> LabResult<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err("certificate file contains no certificates".into());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> LabResult<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::private_key(&mut reader)?
        .ok_or("private key not found in PEM file")?)
}

fn load_roots(path: &Path) -> LabResult<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

fn with_timeouts(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_DEADLINE))?;
    stream.set_write_timeout(Some(IO_DEADLINE))?;
    Ok(())
}

fn serve_once(
    addr: &str,
    ca: &Path,
    certificate: &Path,
    key: &Path,
) -> LabResult<()> {
    // This experimental implementation must never be offered as an Internet service.
    let addr: SocketAddr = addr.parse()?;
    if !addr.ip().is_loopback() {
        return Err("lab server only accepts loopback addresses; not a public VPN".into());
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(load_roots(ca)?))
        .build()?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(certificate)?, load_key(key)?)?;
    let listener = TcpListener::bind(addr)?;
    println!("FedUp mTLS lab listening on {} (one connection only)", listener.local_addr()?);
    let (socket, _) = listener.accept()?;
    with_timeouts(&socket)?;
    let connection = ServerConnection::new(Arc::new(config))?;
    let mut tls = StreamOwned::new(connection, socket);

    // rustls enforces mutual certificate verification before yielding application data.
    let frame = read_frame(&mut tls)?;
    if frame.kind != FrameKind::Ping || frame.stream_id != 0 || frame.payload.len() > MAX_PING_BYTES {
        return Err("lab only accepts one Ping with at most 64 bytes".into());
    }
    let reply = Frame::new(FrameKind::Pong, 0, frame.payload)?;
    write_frame(&mut tls, &reply)?;
    tls.flush()?;
    println!("authenticated laboratory ping completed");
    Ok(())
}

fn send_once(
    addr: &str,
    server_name: &str,
    ca: &Path,
    certificate: &Path,
    key: &Path,
) -> LabResult<()> {
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(load_roots(ca)?)
        .with_client_auth_cert(load_certs(certificate)?, load_key(key)?)?;
    let socket = TcpStream::connect_timeout(&addr.parse::<SocketAddr>()?, IO_DEADLINE)?;
    with_timeouts(&socket)?;
    let sni: ServerName<'static> = ServerName::try_from(server_name.to_owned())?;
    let connection = ClientConnection::new(Arc::new(config), sni)?;
    let mut tls = StreamOwned::new(connection, socket);
    let payload = b"fedup-lab-v1".to_vec();
    write_frame(&mut tls, &Frame::new(FrameKind::Ping, 0, payload.clone())?)?;
    tls.flush()?;
    let reply = read_frame(&mut tls)?;
    if reply.kind != FrameKind::Pong || reply.stream_id != 0 || reply.payload != payload {
        return Err("lab peer returned an unexpected response".into());
    }
    println!("mTLS v1 frame exchange: OK (laboratory only)");
    Ok(())
}

fn usage() {
    eprintln!("FedUp lab (not a VPN):\n\
      fedup-lab server 127.0.0.1:7443 <ca.pem> <server-cert.pem> <server-key.pem>\n\
      fedup-lab client 127.0.0.1:7443 localhost <ca.pem> <client-cert.pem> <client-key.pem>");
}

fn run() -> LabResult<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, mode, addr, ca, cert, key] if mode == "server" => {
            serve_once(addr, Path::new(ca), Path::new(cert), Path::new(key))
        }
        [_, mode, addr, server_name, ca, cert, key] if mode == "client" => {
            send_once(addr, server_name, Path::new(ca), Path::new(cert), Path::new(key))
        }
        _ => {
            usage();
            Err("invalid command-line arguments".into())
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("FedUp lab failed: {err}");
        std::process::exit(1);
    }
}
