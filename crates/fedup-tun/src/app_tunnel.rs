//! Opt-in application-level proof over ordinary TLS 1.3 + real HTTP/2.
//! The front asks for NO TLS client certificate. No device may reach a TUN
//! unless its signed, one-shot application challenge and account are valid.
use super::*;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, SET_COOKIE};

// Ordinary web requests must remain servable while a long-lived upstream
// HTTP/2 VPN stream is active: Caddy can multiplex separate browser clients
// onto the SAME loopback h2c connection. Do not expose device authorization.
fn send_public_page(
    request: &Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &proof::DeviceProof,
    authorization: &DeviceAuthorization,
) -> Result<()> {
    let (status, content_type, body) = public_page(request.method().as_str(), request.uri().path());
    let mut response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(CACHE_CONTROL, "no-store");
    if status == StatusCode::OK
        && request.method() == http::Method::GET
        && request.uri().path() == proof::INIT_PATH
    {
        // Only the cryptographically authenticated device initiation gets a
        // challenge cookie. Every anonymous GET / looks like the same plain
        // public page, with no detectable auth header or special cookie.
        let h = request.headers();
        let value = |key: &str| h.get(key).and_then(|v| v.to_str().ok()).unwrap_or("");
        if let Ok(fp) = state.verify_init(
            value("x-device-init"),
            value("x-device-time"),
            value("x-device-certificate"),
            value("x-device-proof"),
        ) {
            if authorized(authorization, &fp).unwrap_or(false) {
                if let Ok(nonce) = state.issue() {
                    response = response.header(
                        SET_COOKIE,
                        format!(
                            "visitor_session={nonce}; Path=/; Secure; HttpOnly; SameSite=Strict"
                        ),
                    );
                }
            }
        }
    }
    let mut outgoing = respond.send_response(response.body(())?, false)?;
    let payload = if request.method() == http::Method::HEAD {
        Bytes::new()
    } else {
        Bytes::from_static(body)
    };
    outgoing.send_data(payload, true)?;
    Ok(())
}

pub(super) async fn serve<T>(
    tls: T,
    tun: Arc<Tun>,
    authorization: DeviceAuthorization,
    admission: Arc<SessionAdmission>,
    state: Arc<proof::DeviceProof>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = timeout(IO_TIMEOUT, h2_server::handshake(tls)).await??;
    for _ in 0..PUBLIC_MAX_H2_REQUESTS {
        let Some(next) = timeout(PUBLIC_H2_IDLE_TIMEOUT, connection.accept()).await? else {
            break;
        };
        let (request, mut respond) = next?;
        let method = request.method().as_str();
        let path = request.uri().path();
        let protected = (method == "GET" && path == proof::PROBE_PATH)
            || (method == "POST" && path == proof::TUNNEL_PATH && is_h2_request(&request));
        if protected {
            let cookies = request
                .headers()
                .get(COOKIE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let challenge = cookies
                .split(';')
                .map(str::trim)
                .find_map(|cookie| cookie.strip_prefix("visitor_session="))
                .unwrap_or("");
            let certificate = request
                .headers()
                .get("x-device-certificate")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let signature = request
                .headers()
                .get("x-device-proof")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let validated = state
                .verify(challenge, certificate, signature, method, path)
                .and_then(|fp| {
                    if authorized(&authorization, &fp)? {
                        Ok(fp)
                    } else {
                        Err("device no longer permitted".into())
                    }
                });
            let Ok(fp) = validated else {
                send_public_page(&request, respond, &state, &authorization)?;
                continue;
            };
            if method == "GET" {
                respond.send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .header(CACHE_CONTROL, "no-store")
                        .body(())?,
                    true,
                )?;
                continue;
            }
            let _active = match admission.active.clone().try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    respond.send_response(
                        Response::builder()
                            .status(StatusCode::TOO_MANY_REQUESTS)
                            .body(())?,
                        true,
                    )?;
                    continue;
                }
            };
            let outgoing = respond.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, H2_TYPE)
                    .body(())?,
                false,
            )?;
            let (tun_end, bridge_end) = duplex(64 * 1024);
            let bridge = tokio::spawn(h2_bridge(request.into_body(), outgoing, bridge_end));
            let browser_sessions = state.clone();
            let web_authorization = authorization.clone();
            let driver = tokio::spawn(async move {
                while let Some(next) = connection.accept().await {
                    let (request, respond) = next?;
                    // Keep public web and invalid protected URLs on exactly
                    // the same fallback route, even while TUN is active.
                    // The second packet stream remains denied (404).
                    send_public_page(&request, respond, &browser_sessions, &web_authorization)?;
                }
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
            let result = forward(tun_end, tun, false, Some((authorization, fp)), true).await;
            driver.abort();
            bridge.abort();
            return result;
        }

        send_public_page(&request, respond, &state, &authorization)?;
    }
    connection.graceful_shutdown();
    let _ = timeout(Duration::from_secs(2), connection.accept()).await;
    Ok(())
}
