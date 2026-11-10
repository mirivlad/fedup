//! Isolated Linux test client for HTTPS/2 + one-time application device proof.
//! The outer TLS handshake intentionally presents no client certificate.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use rand::{rngs::OsRng, RngCore};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_openssl::SslStream;

fn headers_for_proof(
    cert_der: &[u8],
    key_der: &[u8],
    method: &str,
    path: &str,
    nonce: &str,
) -> Result<(String, String)> {
    let fingerprint = fingerprint(cert_der);
    let message = proof::message(method, path, nonce, &fingerprint);
    let key = PKey::private_key_from_der(key_der)?;
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;
    signer.update(message.as_bytes())?;
    Ok((
        URL_SAFE_NO_PAD.encode(cert_der),
        URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?),
    ))
}

async fn get_challenge(
    sender: &mut h2_client::SendRequest<Bytes>,
    hostname: &str,
    cert_der: &[u8],
    private_der: &[u8],
) -> Result<String> {
    *sender = timeout(IO_TIMEOUT, sender.clone().ready()).await??;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let init = URL_SAFE_NO_PAD.encode(raw);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let fp = fingerprint(cert_der);
    let signed = proof::init_message(&init, &timestamp, &fp);
    let key = PKey::private_key_from_der(private_der)?;
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;
    signer.update(signed.as_bytes())?;
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{hostname}{}", proof::INIT_PATH))
        .header("x-device-init", init)
        .header("x-device-time", timestamp)
        .header("x-device-certificate", URL_SAFE_NO_PAD.encode(cert_der))
        .header(
            "x-device-proof",
            URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?),
        )
        .body(())?;
    let (response, _) = sender.send_request(request, true)?;
    let response = timeout(IO_TIMEOUT, response).await??;
    if response.status() != StatusCode::OK {
        return Err("public HTTPS page unavailable".into());
    }
    let cookie = response
        .headers()
        .get(http::header::SET_COOKIE)
        .ok_or("no web session cookie from gateway")?
        .to_str()?;
    let challenge = cookie
        .split(';')
        .next()
        .and_then(|s| s.strip_prefix("visitor_session="))
        .ok_or("unexpected web session cookie")?;
    if challenge.len() != 43 {
        return Err("invalid web session nonce length".into());
    }
    Ok(challenge.to_owned())
}

pub(super) async fn connect(
    server: SocketAddr,
    tun_name: &str,
    directory: &Path,
    password_stdin: bool,
    auth_only: bool,
    openssl_tls: bool,
) -> Result<()> {
    require_isolated_network_namespace()?;
    if !private_lab_ip(server) {
        return Err("app-proof experimental client must use an isolated private server".into());
    }
    let device = device_connection(directory)?;
    let passphrase = read_password(false, password_stdin)?;
    let private = decrypt_pkcs8(&device.encrypted_key_path, passphrase.as_bytes())?;
    let certs = ca_certs(&device.cert_path)?;
    let cert_der = certs.first().ok_or("missing device certificate")?.as_ref();
    let hostname = device.server_name;
    if openssl_tls {
        // Experimental comparison with ordinary curl/OpenSSL: use the
        // *unmodified* standard OpenSSL ClientHello rather than manufacturing
        // a TLS fingerprint. Verification of CA, DNS name and ALPN is still
        // mandatory; device identity is checked by signed HTTP application proof.
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_ca_file(&device.ca_path)?;
        builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
        let ssl = builder
            .build()
            .configure()?
            .verify_hostname(true)
            .into_ssl(&hostname)?;
        let socket = timeout(IO_TIMEOUT, TcpStream::connect(server)).await??;
        let mut tls = SslStream::new(ssl, socket)?;
        timeout(IO_TIMEOUT, Pin::new(&mut tls).connect()).await??;
        if tls.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
            return Err("OpenSSL client did not negotiate real HTTP/2".into());
        }
        return run_h2(
            tls,
            tun_name,
            &hostname,
            cert_der,
            private.as_ref(),
            auth_only,
        )
        .await;
    }

    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots(&device.ca_path)?)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let socket = timeout(IO_TIMEOUT, TcpStream::connect(server)).await??;
    let server_name: ServerName<'static> = ServerName::try_from(hostname.clone())?;
    let tls = timeout(IO_TIMEOUT, connector.connect(server_name, socket)).await??;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("app-proof gateway did not negotiate real HTTP/2".into());
    }
    run_h2(
        tls,
        tun_name,
        &hostname,
        cert_der,
        private.as_ref(),
        auth_only,
    )
    .await
}

async fn run_h2<S>(
    tls: S,
    tun_name: &str,
    hostname: &str,
    cert_der: &[u8],
    private_der: &[u8],
    auth_only: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = timeout(IO_TIMEOUT, h2_client::handshake(tls)).await??;
    let driver = tokio::spawn(connection);
    let nonce = get_challenge(&mut sender, hostname, cert_der, private_der).await?;
    let (cert, signature) = headers_for_proof(
        cert_der,
        private_der,
        if auth_only { "GET" } else { "POST" },
        if auth_only {
            proof::PROBE_PATH
        } else {
            proof::TUNNEL_PATH
        },
        &nonce,
    )?;
    sender = timeout(IO_TIMEOUT, sender.ready()).await??;
    let mut request = Request::builder()
        .method(if auth_only {
            http::Method::GET
        } else {
            http::Method::POST
        })
        .uri(format!(
            "https://{hostname}{}",
            if auth_only {
                proof::PROBE_PATH
            } else {
                proof::TUNNEL_PATH
            }
        ))
        .header(http::header::COOKIE, format!("visitor_session={nonce}"))
        .header("x-device-certificate", cert)
        .header("x-device-proof", signature);
    if !auth_only {
        request = request.header(http::header::CONTENT_TYPE, H2_TYPE);
    }
    let (response, outgoing) = sender.send_request(request.body(())?, auth_only)?;
    let response = timeout(IO_TIMEOUT, response).await??;
    if auth_only {
        if response.status() != StatusCode::NO_CONTENT {
            return Err("application device proof denied".into());
        }
        println!("FedUp application proof via normal HTTPS/2 accepted, no TUN created");
        driver.abort();
        return Ok(());
    }
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_none_or(|h| h != H2_TYPE)
    {
        return Err("application-authorized packet tunnel rejected".into());
    }
    let (tun_end, bridge_end) = duplex(64 * 1024);
    let bridge = tokio::spawn(h2_bridge(response.into_body(), outgoing, bridge_end));
    let tun = create_tun(tun_name)?;
    println!("FedUp application-key proof accepted; isolated VPS IPv4 TUN ready");
    let result = forward(tun_end, tun, true, None, true).await;
    bridge.abort();
    driver.abort();
    result
}
