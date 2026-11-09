//! Local-only authentication API for a trusted HTTPS reverse proxy.
//!
//! Ordinary mode checks passwords only. Explicit unsafe-lab-enroll mode
//! automatically signs short-lived device CSRs and links them to accounts.
//! Never bind to a public NIC or use the lab issuer CA key in production.
//! Reverse proxy MUST authenticate its own TLS certificate and disable caching.

use axum::extract::{DefaultBodyLimit, Json, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Json as JsonResponse;
use axum::Router;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
mod issuer;
use issuer::LabIssuer;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}

struct Limits {
    global: (Instant, u32),
    users: HashMap<String, (Instant, u32)>,
}

impl Limits {
    fn allow(&mut self, username: &str) -> bool {
        let now = Instant::now();
        // Global cap prevents hundreds of Argon2id hashes from consuming all
        // RAM/CPU, including attacks using unique unknown usernames.
        if now.duration_since(self.global.0) >= Duration::from_secs(60) {
            self.global = (now, 0);
            self.users.clear();
        }
        if self.global.1 >= 100 {
            return false;
        }
        self.global.1 += 1;
        if self.users.len() >= 512 && !self.users.contains_key(username) {
            return false;
        }
        let entry = self.users.entry(username.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(60) {
            *entry = (now, 0);
        }
        if entry.1 >= 10 {
            return false;
        }
        entry.1 += 1;
        true
    }
}

struct App {
    users: PathBuf,
    attempts: Mutex<Limits>,
    workers: Arc<Semaphore>,
    issuer: Option<LabIssuer>,
}

impl App {
    fn new(users: PathBuf, issuer: Option<LabIssuer>) -> Self {
        Self {
            users,
            attempts: Mutex::new(Limits {
                global: (Instant::now(), 0),
                users: HashMap::new(),
            }),
            workers: Arc::new(Semaphore::new(4)),
            issuer,
        }
    }
}

fn reply(status: StatusCode) -> impl IntoResponse {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
    )
}

async fn password_valid(state: &Arc<App>, input: Login) -> std::result::Result<bool, StatusCode> {
    if input.username.len() > 48
        || input.password.len() > 128
        || input.username.is_empty()
        || input.password.is_empty()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !state.attempts.lock().await.allow(&input.username) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Do not queue an unbounded number of password hashes.
    let Ok(permit) = state.workers.clone().try_acquire_owned() else {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    };
    let user = input.username;
    let password = Zeroizing::new(input.password.into_bytes());
    let users = state.users.clone();
    let result = tokio::task::spawn_blocking(move || {
        let result = fedup_users::authenticate(&users, &user, &password);
        drop(permit);
        result
    })
    .await;
    Ok(matches!(result, Ok(Ok(true))))
}

async fn login(State(state): State<Arc<App>>, Json(input): Json<Login>) -> impl IntoResponse {
    match password_valid(&state, input).await {
        Ok(true) => reply(StatusCode::NO_CONTENT),
        Ok(false) | Err(StatusCode::UNAUTHORIZED) => reply(StatusCode::UNAUTHORIZED),
        Err(code) => reply(code),
    }
}

/// Do not disclose device CA or transport mode to anonymous active probes.
/// Requires the SAME login/password as enrollment and uses the shared rate cap.
#[derive(Serialize)]
struct AuthenticatedConfig {
    #[serde(flatten)]
    device_ca: issuer::PublicConfig,
    transport: &'static str,
    tunnel_port: u16,
}

async fn enrollment_config(State(state): State<Arc<App>>, Json(input): Json<Login>) -> Response {
    let Some(issuer) = &state.issuer else {
        return reply(StatusCode::SERVICE_UNAVAILABLE).into_response();
    };
    match password_valid(&state, input).await {
        Ok(true) => {}
        Err(StatusCode::TOO_MANY_REQUESTS) => {
            return reply(StatusCode::TOO_MANY_REQUESTS).into_response();
        }
        _ => return reply(StatusCode::NOT_FOUND).into_response(),
    }
    // Enable only when the administrator has configured Caddy and the
    // loopback h2c gateway. Never infer readiness from this environment flag.
    let stealth = env::var("FEDUP_VPN_PROOF_EDGE").ok().as_deref() == Some("1");
    let mut response = JsonResponse(AuthenticatedConfig {
        device_ca: issuer.public_config(),
        transport: if stealth { "app-proof" } else { "mtls" },
        tunnel_port: if stealth { 443 } else { 7443 },
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRequest {
    username: String,
    password: String,
    device: String,
    csr_pem: String,
}

/// The same password rate limiting policy applies to device provisioning.
/// Issuance is bounded and happens on a worker, with a transaction checking
/// that no password reset, disable or revision change occurred meanwhile.
async fn enroll_device(
    State(state): State<Arc<App>>,
    Json(input): Json<DeviceRequest>,
) -> Response {
    let Some(issuer) = state.issuer.clone() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE).into_response();
    };
    if input.username.len() > 48
        || input.username.is_empty()
        || input.password.len() > 128
        || input.password.is_empty()
        || input.device.is_empty()
        || input.device.len() > 48
        || input.csr_pem.len() > 8192
        || input.csr_pem.is_empty()
    {
        return reply(StatusCode::UNAUTHORIZED).into_response();
    }
    if !state.attempts.lock().await.allow(&input.username) {
        return reply(StatusCode::TOO_MANY_REQUESTS).into_response();
    }
    let Ok(permit) = state.workers.clone().try_acquire_owned() else {
        return reply(StatusCode::TOO_MANY_REQUESTS).into_response();
    };
    let users = state.users.clone();
    let device = input.device;
    let csr_pem = input.csr_pem;
    let username = input.username;
    let password = Zeroizing::new(input.password.into_bytes());
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let revision = fedup_users::authenticate_revision(&users, &username, &password)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .ok_or(StatusCode::UNAUTHORIZED)?;
        // The signature on the CSR proves the client holds the corresponding
        // private key. We never receive or store its private key.
        let mut issued = issuer
            .issue(&csr_pem, &device)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let csr_sha256 = hex::encode(Sha256::digest(csr_pem.as_bytes()));
        let (saved_cert, saved_fp) = fedup_users::register_signed_device(
            &users,
            fedup_users::SignedDevice {
                username: &username,
                revision,
                label: &device,
                csr_sha256: &csr_sha256,
                fingerprint: &issued.fingerprint_sha256,
                expires_at: issued.expires_at,
                certificate_pem: &issued.certificate_pem,
            },
        )
        .map_err(|_| StatusCode::CONFLICT)?;
        // Duplicate, authenticated retries receive the same originally
        // issued cert. Never create multiple active certs after a lost reply.
        issued.certificate_pem = saved_cert;
        issued.fingerprint_sha256 = saved_fp;
        Ok::<_, StatusCode>(issued)
    })
    .await;

    match task {
        Ok(Ok(issued)) => {
            let mut response = (StatusCode::CREATED, JsonResponse(issued)).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            response
        }
        Ok(Err(status)) => reply(status).into_response(),
        Err(_) => reply(StatusCode::SERVICE_UNAVAILABLE).into_response(),
    }
}

fn app(users: PathBuf, issuer: Option<LabIssuer>) -> Router {
    Router::new()
        .route(
            "/api/fedup/v1/login",
            post(login).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/api/fedup/v1/devices",
            post(enroll_device).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/api/fedup/v1/config",
            post(enrollment_config)
                .get(|| async { StatusCode::NOT_FOUND })
                .layer(DefaultBodyLimit::max(2048)),
        )
        .with_state(Arc::new(App::new(users, issuer)))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (state, port, issuer) = match args.as_slice() {
        [_, cmd, state, port, flag]
            if cmd == "serve" && flag == "--behind-https-proxy" =>
        {
            (state.as_str(), port.as_str(), None)
        }
        [_, cmd, state, port, ca, ca_key, name, flag]
            if cmd == "serve-enroll-lab" && flag == "--unsafe-lab-online-ca" =>
        {
            let lab = LabIssuer::load(Path::new(ca), Path::new(ca_key), name)?;
            (state.as_str(), port.as_str(), Some(lab))
        }
        _ => return Err("usage: fedup-auth serve <users-dir> <port> --behind-https-proxy
    or: fedup-auth serve-enroll-lab <users-dir> <port> <ca.pem> <CA-KEY.pem> <server-name> --unsafe-lab-online-ca
The lab signer is NOT safe for any real CA or production VPN.".into()),
    };
    let port: u16 = port.parse()?;
    if port == 0 {
        return Err("port 0 is not supported".into());
    }
    // Fail at startup if account storage is missing/permissions invalid.
    let _ = fedup_users::authenticate(
        std::path::Path::new(state),
        "startup_probe_missing_user",
        b"unprivileged-health-check-only",
    )?;
    let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("FedUp auth only on {bind} — MUST use trusted HTTPS reverse proxy");
    axum::serve(listener, app(PathBuf::from(state), issuer)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn per_user_and_global_rate_limiter() {
        let mut attempts = Limits {
            global: (Instant::now(), 0),
            users: HashMap::new(),
        };
        for _ in 0..10 {
            assert!(attempts.allow("alice"));
        }
        assert!(!attempts.allow("alice"));
        assert!(attempts.allow("bob"));
        for i in 0..88 {
            assert!(attempts.allow(&format!("guest{i}")));
        }
        assert!(!attempts.allow("guest-new"));
    }

    #[tokio::test]
    async fn empty_password_is_never_authorized() {
        let app = app(PathBuf::from("/nonexistent-accounts"), None);
        let req = Request::post("/api/fedup/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"username":"alice","password":""}"#))
            .unwrap();
        let answer = app.oneshot(req).await.unwrap();
        assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(answer.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn oversized_body_is_refused() {
        let app = app(PathBuf::from("/nonexistent-accounts"), None);
        let request = Request::post("/api/fedup/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("A".repeat(4096)))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
