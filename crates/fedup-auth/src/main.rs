//! Local-only authentication API for a trusted HTTPS reverse proxy.
//!
//! This endpoint checks passwords; it does NOT issue VPN certificates,
//! register devices, or grant a VPN session yet. Never bind to a public NIC.
//! Reverse proxy MUST authenticate its own TLS certificate and disable caching.

use axum::extract::{DefaultBodyLimit, Json, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
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
}

impl App {
    fn new(users: PathBuf) -> Self {
        Self {
            users,
            attempts: Mutex::new(Limits {
                global: (Instant::now(), 0),
                users: HashMap::new(),
            }),
            workers: Arc::new(Semaphore::new(4)),
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

async fn login(State(state): State<Arc<App>>, Json(input): Json<Login>) -> impl IntoResponse {
    if input.username.len() > 48
        || input.password.len() > 128
        || input.username.is_empty()
        || input.password.is_empty()
    {
        return reply(StatusCode::UNAUTHORIZED);
    }
    if !state.attempts.lock().await.allow(&input.username) {
        return reply(StatusCode::TOO_MANY_REQUESTS);
    }
    // Do not queue an unbounded number of password hashes.
    let Ok(permit) = state.workers.clone().try_acquire_owned() else {
        return reply(StatusCode::TOO_MANY_REQUESTS);
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
    if matches!(result, Ok(Ok(true))) {
        reply(StatusCode::NO_CONTENT)
    } else {
        reply(StatusCode::UNAUTHORIZED)
    }
}

fn app(users: PathBuf) -> Router {
    Router::new()
        .route("/api/fedup/v1/login", post(login))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(Arc::new(App::new(users)))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, cmd, state, port, flag] = args.as_slice() else {
        return Err(
            "usage: fedup-auth serve <private-users-dir> <port> --behind-https-proxy".into(),
        );
    };
    if cmd != "serve" || flag != "--behind-https-proxy" {
        return Err("explicit --behind-https-proxy confirmation required".into());
    }
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
    axum::serve(listener, app(PathBuf::from(state))).await?;
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
        for i in 0..89 {
            assert!(attempts.allow(&format!("guest{i}")));
        }
        assert!(!attempts.allow("guest-new"));
    }

    #[tokio::test]
    async fn empty_password_is_never_authorized() {
        let app = app(PathBuf::from("/nonexistent-accounts"));
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
        let app = app(PathBuf::from("/nonexistent-accounts"));
        let request = Request::post("/api/fedup/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("A".repeat(4096)))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
