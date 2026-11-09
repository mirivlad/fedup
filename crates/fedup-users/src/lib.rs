//! FedUp operator-managed user accounts.
//!
//! Passwords are read from stdin, NEVER from argv or environment variables.
//! Password verifiers are salted Argon2id (RFC 9106-style parameters).
//! This is *not* yet a network-login endpoint or full VPN.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::env;
use std::error::Error;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const DB_FILE: &str = "users.sqlite3";
const PASSWORD_MIN: usize = 12;
const PASSWORD_MAX: usize = 128;
const MAX_USERS: i64 = 256;

fn valid_username(name: &str) -> bool {
    (1..=48).contains(&name.len())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

fn hash_config() -> Result<Argon2<'static>> {
    // Argon2id, 19 MiB, 2 passes, one thread. Parameters are stored in PHC.
    // Authentication servers must additionally rate-limit at the network edge.
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None)?,
    ))
}

fn hash_password(password: &[u8]) -> Result<String> {
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&password.len()) || password.contains(&0) {
        return Err("password must be 12-128 bytes, without NUL".into());
    }
    let salt = SaltString::generate(&mut OsRng);
    Ok(hash_config()?.hash_password(password, &salt)?.to_string())
}

fn verify_password(phc: &str, password: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != "argon2id" {
        return false;
    }
    // Do not trust arbitrary PHC memory parameters in a modified database.
    if parsed.params.get_decimal("m") != Some(19 * 1024)
        || parsed.params.get_decimal("t") != Some(2)
        || parsed.params.get_decimal("p") != Some(1)
    {
        return false;
    }
    hash_config().is_ok_and(|argon| argon.verify_password(password, &parsed).is_ok())
}

fn state_path(dir: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err("user directory must be an ordinary private directory (0700)".into());
    }
    let path = dir.join(DB_FILE);
    let db = fs::symlink_metadata(&path)?;
    if !db.is_file() || db.file_type().is_symlink() || db.permissions().mode() & 0o077 != 0 {
        return Err("user database must be an ordinary private file (0600)".into());
    }
    Ok(path)
}

fn connection(dir: &Path) -> Result<Connection> {
    let path = state_path(dir)?;
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(Duration::from_secs(10))?;
    db.execute_batch("PRAGMA foreign_keys=ON;")?;
    Ok(db)
}

fn init(dir: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(dir)?;
    let path = dir.join(DB_FILE);
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.sync_all()?;
    let db = connection(dir)?;
    db.execute_batch(
        "CREATE TABLE users (
            username TEXT PRIMARY KEY NOT NULL,
            password_phc TEXT NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
            revision INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE devices (
            fingerprint TEXT PRIMARY KEY NOT NULL,
            username TEXT NOT NULL REFERENCES users(username),
            label TEXT NOT NULL,
            revision INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
            csr_sha256 TEXT,
            certificate_pem TEXT,
            UNIQUE(username, label)
        );
        CREATE INDEX devices_by_owner ON devices(username);",
    )?;
    Ok(())
}

fn add(dir: &Path, username: &str, password: &[u8]) -> Result<()> {
    if !valid_username(username) {
        return Err("username must be 1-48 lowercase ASCII letters, numbers, dots, _ or -".into());
    }
    let phc = hash_password(password)?;
    let mut db = connection(dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let count: i64 = tx.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
    if count >= MAX_USERS {
        return Err("user limit reached".into());
    }
    tx.execute(
        "INSERT INTO users(username,password_phc) VALUES (?1,?2)",
        params![username, phc],
    )?;
    tx.commit()?;
    Ok(())
}

fn change_password(dir: &Path, username: &str, password: &[u8]) -> Result<()> {
    if !valid_username(username) {
        return Err("invalid username".into());
    }
    let phc = hash_password(password)?;
    let db = connection(dir)?;
    if db.execute(
        "UPDATE users SET password_phc=?2, revision=revision+1 WHERE username=?1",
        params![username, phc],
    )? != 1
    {
        return Err("user not found".into());
    }
    Ok(())
}

fn disable(dir: &Path, username: &str, disabled: bool) -> Result<()> {
    if !valid_username(username) {
        return Err("invalid username".into());
    }
    let db = connection(dir)?;
    if db.execute(
        "UPDATE users SET disabled=?2,revision=revision+1 WHERE username=?1",
        params![username, i64::from(disabled)],
    )? != 1
    {
        return Err("user not found".into());
    }
    Ok(())
}

/// Return the exact revision authenticated by the password. An issuer MUST
/// compare this revision inside its registration transaction to prevent a
/// concurrent password reset from registering a new device.
pub fn authenticate_revision(dir: &Path, username: &str, password: &[u8]) -> Result<Option<i64>> {
    if !valid_username(username) || password.len() > PASSWORD_MAX || password.is_empty() {
        return Ok(None);
    }
    let db = connection(dir)?;
    let record: Option<(String, bool, i64)> = db
        .query_row(
            "SELECT password_phc,disabled,revision FROM users WHERE username=?1",
            [username],
            |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0, row.get(2)?)),
        )
        .optional()?;
    let dummy = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXJhbmRvbXNhbHQxMjM0NTY$+w/0X+MZSTWzPmM9EFhYQexbawefxG4TOGsvrPD/GHA";
    let (phc, disabled, revision, found) = match record {
        Some((hash, blocked, revision)) => (hash, blocked, revision, true),
        None => (dummy.to_owned(), true, 0, false),
    };
    let valid = verify_password(&phc, password);
    if found && !disabled && valid {
        Ok(Some(revision))
    } else {
        Ok(None)
    }
}

pub fn authenticate(dir: &Path, username: &str, password: &[u8]) -> Result<bool> {
    Ok(authenticate_revision(dir, username, password)?.is_some())
}

/// Link a signed cert fingerprint to a user only when their *same*
/// authenticated account revision is still active. Revoking or changing
/// the user's password invalidates all devices immediately on next check.
pub fn register_device(
    dir: &Path,
    username: &str,
    revision: i64,
    label: &str,
    fingerprint: &str,
    expires_at: i64,
) -> Result<()> {
    if !valid_username(username)
        || !valid_username(label)
        || fingerprint.len() != 64
        || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        || expires_at <= unix_seconds()?
    {
        return Err("invalid device metadata".into());
    }
    let mut db = connection(dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active: bool = tx
        .query_row(
            "SELECT disabled=0 AND revision=?2 FROM users WHERE username=?1",
            params![username, revision],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false);
    if !active {
        return Err("account disabled or changed during enrollment".into());
    }
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM devices WHERE username=?1 AND disabled=0 AND revision=?2",
        params![username, revision],
        |r| r.get(0),
    )?;
    if count >= 8 {
        return Err("device limit reached".into());
    }
    tx.execute(
        "INSERT INTO devices(fingerprint,username,label,revision,expires_at)
         VALUES (?1,?2,?3,?4,?5)",
        params![
            fingerprint.to_ascii_lowercase(),
            username,
            label,
            revision,
            expires_at
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// Idempotent registration for exactly the same signed CSR, user account
/// revision and device label. If a response is lost the phone can safely
/// retry using the same protected key instead of generating an orphan identity.
#[derive(Clone, Copy)]
pub struct SignedDevice<'a> {
    pub username: &'a str,
    pub revision: i64,
    pub label: &'a str,
    pub csr_sha256: &'a str,
    pub fingerprint: &'a str,
    pub expires_at: i64,
    pub certificate_pem: &'a str,
}

struct ExistingDevice {
    csr_sha256: Option<String>,
    certificate_pem: Option<String>,
    fingerprint: String,
    revision: i64,
    expires_at: i64,
    disabled: bool,
}

/// Idempotent registration for the same CSR+account revision. A lost HTTP
/// response does not strand the phone or accidentally issue a second cert.
pub fn register_signed_device(dir: &Path, device: SignedDevice<'_>) -> Result<(String, String)> {
    let SignedDevice {
        username,
        revision,
        label,
        csr_sha256,
        fingerprint,
        expires_at,
        certificate_pem,
    } = device;
    if !valid_username(username)
        || !valid_username(label)
        || csr_sha256.len() != 64
        || !csr_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || fingerprint.len() != 64
        || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        || certificate_pem.len() > 8192
        || !certificate_pem.starts_with("-----BEGIN CERTIFICATE-----")
        || expires_at <= unix_seconds()?
    {
        return Err("invalid signed device request".into());
    }
    let mut db = connection(dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active = tx
        .query_row(
            "SELECT disabled=0 AND revision=?2 FROM users WHERE username=?1",
            params![username, revision],
            |row| row.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(false);
    if !active {
        return Err("account disabled or changed while signing".into());
    }
    let existing = tx
        .query_row(
            "SELECT csr_sha256,certificate_pem,fingerprint,revision,expires_at,disabled
             FROM devices WHERE username=?1 AND label=?2",
            params![username, label],
            |row| {
                Ok(ExistingDevice {
                    csr_sha256: row.get(0)?,
                    certificate_pem: row.get(1)?,
                    fingerprint: row.get(2)?,
                    revision: row.get(3)?,
                    expires_at: row.get(4)?,
                    disabled: row.get(5)?,
                })
            },
        )
        .optional()?;
    if let Some(saved) = existing {
        if !saved.disabled
            && saved.revision == revision
            && saved.expires_at > unix_seconds()?
            && saved.csr_sha256.as_deref() == Some(csr_sha256)
        {
            let cert = saved.certificate_pem.ok_or("missing certificate on safe retry")?;
            tx.commit()?;
            return Ok((cert, saved.fingerprint));
        }
        return Err("device label already in use or invalidated".into());
    }
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM devices WHERE username=?1 AND revision=?2 AND disabled=0",
        params![username, revision],
        |row| row.get(0),
    )?;
    if count >= 8 {
        return Err("eight-device limit reached".into());
    }
    tx.execute(
        "INSERT INTO devices(fingerprint,username,label,revision,expires_at,csr_sha256,certificate_pem)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            fingerprint.to_ascii_lowercase(),
            username,
            label,
            revision,
            expires_at,
            csr_sha256.to_ascii_lowercase(),
            certificate_pem,
        ],
    )?;
    tx.commit()?;
    Ok((certificate_pem.to_owned(), fingerprint.to_ascii_lowercase()))
}

pub fn authorized_device(dir: &Path, fingerprint: &str) -> Result<bool> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(false);
    }
    let db = connection(dir)?;
    let active: Option<bool> = db
        .query_row(
            "SELECT u.disabled=0 AND d.disabled=0 AND d.revision=u.revision
                    AND d.expires_at>?2
             FROM devices d JOIN users u ON u.username=d.username
             WHERE d.fingerprint=?1",
            params![fingerprint.to_ascii_lowercase(), unix_seconds()?],
            |row| row.get(0),
        )
        .optional()?;
    Ok(active.unwrap_or(false))
}

pub fn revoke_device(dir: &Path, fingerprint: &str) -> Result<()> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected SHA256 certificate fingerprint".into());
    }
    let db = connection(dir)?;
    if db.execute(
        "UPDATE devices SET disabled=1 WHERE fingerprint=?1 AND disabled=0",
        [fingerprint.to_ascii_lowercase()],
    )? != 1
    {
        return Err("active device not found".into());
    }
    Ok(())
}

fn unix_seconds() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64)
}

fn migrate_devices(dir: &Path) -> Result<()> {
    let db = connection(dir)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS devices (
            fingerprint TEXT PRIMARY KEY NOT NULL,
            username TEXT NOT NULL REFERENCES users(username),
            label TEXT NOT NULL,
            revision INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
            csr_sha256 TEXT,
            certificate_pem TEXT,
            UNIQUE(username,label)
        );
        CREATE INDEX IF NOT EXISTS devices_by_owner ON devices(username);",
    )?;
    let mut columns = Vec::new();
    let mut statement = db.prepare("PRAGMA table_info(devices)")?;
    for col in statement.query_map([], |r| r.get::<_, String>(1))? {
        columns.push(col?);
    }
    if !columns.iter().any(|c| c == "csr_sha256") {
        db.execute_batch("ALTER TABLE devices ADD COLUMN csr_sha256 TEXT;")?;
    }
    if !columns.iter().any(|c| c == "certificate_pem") {
        db.execute_batch("ALTER TABLE devices ADD COLUMN certificate_pem TEXT;")?;
    }
    Ok(())
}

fn list_devices(dir: &Path, username: &str) -> Result<()> {
    if !valid_username(username) {
        return Err("invalid username".into());
    }
    let db = connection(dir)?;
    let mut statement = db.prepare(
        "SELECT fingerprint,label,revision,expires_at,disabled
         FROM devices WHERE username=?1 ORDER BY label",
    )?;
    let items = statement.query_map([username], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, bool>(4)?,
        ))
    })?;
    for item in items {
        let (fingerprint, label, revision, expires, disabled) = item?;
        println!(
            "{label}\t{fingerprint}\taccount_revision={revision}\texpires={expires}\t{}",
            if disabled { "revoked" } else { "issued" }
        );
    }
    Ok(())
}

fn list(dir: &Path) -> Result<()> {
    let db = connection(dir)?;
    let mut query = db.prepare("SELECT username,disabled FROM users ORDER BY username")?;
    let records = query.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
    })?;
    for record in records {
        let (user, disabled) = record?;
        println!("{user}\t{}", if disabled { "disabled" } else { "active" });
    }
    Ok(())
}

fn stdin_password() -> Result<Zeroizing<Vec<u8>>> {
    let mut password = Zeroizing::new(Vec::new());
    io::stdin()
        .take((PASSWORD_MAX + 2) as u64)
        .read_to_end(&mut password)?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&password.len()) || password.contains(&0) {
        return Err("password must be 12-128 bytes (stdin), without NUL".into());
    }
    Ok(password)
}

fn usage() {
    eprintln!(
        "FedUp local user administration (NOT a public login endpoint):\n\
         fedup-users init <private-users-dir>\n\
         fedup-users add <users-dir> <username> --password-stdin\n\
         fedup-users password <users-dir> <username> --password-stdin\n\
         fedup-users disable <users-dir> <username>\n\
         fedup-users enable <users-dir> <username>\n\
         fedup-users list <users-dir>\n\
         fedup-users migrate <users-dir>\n\
         fedup-users devices <users-dir> <username>\n\
         fedup-users check-device <users-dir> <cert-sha256>\n\
         fedup-users revoke-device <users-dir> <cert-sha256>\n\
         fedup-users check <users-dir> <username> --password-stdin\n\
         Passwords must NEVER be passed in argv or shell environment variables."
    );
}

pub fn run_cli() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, cmd, dir] if cmd == "init" => init(Path::new(dir)),
        [_, cmd, dir] if cmd == "list" => list(Path::new(dir)),
        [_, cmd, dir] if cmd == "migrate" => migrate_devices(Path::new(dir)),
        [_, cmd, dir, username] if cmd == "devices" => list_devices(Path::new(dir), username),
        [_, cmd, dir, fingerprint] if cmd == "check-device" => {
            if authorized_device(Path::new(dir), fingerprint)? {
                println!("device authorized");
                Ok(())
            } else {
                Err("device not authorized".into())
            }
        }
        [_, cmd, dir, user, flag] if cmd == "add" && flag == "--password-stdin" => {
            let pass = stdin_password()?;
            add(Path::new(dir), user, &pass)
        }
        [_, cmd, dir, user, flag] if cmd == "password" && flag == "--password-stdin" => {
            let pass = stdin_password()?;
            change_password(Path::new(dir), user, &pass)
        }
        [_, cmd, dir, user] if cmd == "disable" => disable(Path::new(dir), user, true),
        [_, cmd, dir, user] if cmd == "enable" => disable(Path::new(dir), user, false),
        [_, cmd, dir, fingerprint] if cmd == "revoke-device" => {
            revoke_device(Path::new(dir), fingerprint)
        }
        [_, cmd, dir, user, flag] if cmd == "check" && flag == "--password-stdin" => {
            let pass = stdin_password()?;
            if authenticate(Path::new(dir), user, &pass)? {
                println!("FedUp user credentials: valid");
                Ok(())
            } else {
                Err("authentication failed".into())
            }
        }
        _ => {
            usage();
            Err("invalid arguments".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn isolated() -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fedup-users-test-{}-{}", std::process::id(), id));
        init(&dir).unwrap();
        dir
    }

    #[test]
    fn lifecycle_and_disable_revoke_password_auth() {
        let dir = isolated();
        let p1 = b"very-long-example-passphrase";
        let p2 = b"another-long-example-passphrase";
        add(&dir, "family.phone", p1).unwrap();
        assert!(authenticate(&dir, "family.phone", p1).unwrap());
        assert!(!authenticate(&dir, "family.phone", b"incorrect-user-password").unwrap());
        assert!(!authenticate(&dir, "missing", p1).unwrap());
        disable(&dir, "family.phone", true).unwrap();
        assert!(!authenticate(&dir, "family.phone", p1).unwrap());
        disable(&dir, "family.phone", false).unwrap();
        change_password(&dir, "family.phone", p2).unwrap();
        assert!(!authenticate(&dir, "family.phone", p1).unwrap());
        assert!(authenticate(&dir, "family.phone", p2).unwrap());
        assert!(add(&dir, "family.phone", p2).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_name_password_and_symlink_refused() {
        let dir = isolated();
        assert!(add(&dir, "../../etc", b"very-long-example-passphrase").is_err());
        assert!(add(&dir, "MixedCase", b"very-long-example-passphrase").is_err());
        assert!(add(&dir, "alice", b"short").is_err());
        let target = dir
            .parent()
            .unwrap()
            .join("fedup-users-untrusted-symlink-test");
        let _ = fs::remove_file(&target);
        std::os::unix::fs::symlink(&dir, &target).unwrap();
        assert!(connection(&target).is_err());
        fs::remove_file(target).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phc_store_has_no_plaintext_and_uses_argon2id() {
        let dir = isolated();
        let password = b"example-long-secret-phrase";
        add(&dir, "alice", password).unwrap();
        let db = connection(&dir).unwrap();
        let hash: String = db
            .query_row(
                "SELECT password_phc FROM users WHERE username='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(!hash.contains("example-long-secret"));
        assert!(verify_password(&hash, password));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn account_revision_revokes_all_devices_and_prevents_stale_enrollments() {
        let dir = isolated();
        let pass = b"long-test-passphrase-device";
        add(&dir, "family", pass).unwrap();
        let revision = authenticate_revision(&dir, "family", pass)
            .unwrap()
            .unwrap();
        let fp = "a1".repeat(32);
        register_device(
            &dir,
            "family",
            revision,
            "phone",
            &fp,
            unix_seconds().unwrap() + 600,
        )
        .unwrap();
        assert!(authorized_device(&dir, &fp).unwrap());
        assert!(register_device(
            &dir,
            "family",
            revision,
            "phone",
            &"b1".repeat(32),
            unix_seconds().unwrap() + 600
        )
        .is_err());
        disable(&dir, "family", true).unwrap();
        assert!(!authorized_device(&dir, &fp).unwrap());
        disable(&dir, "family", false).unwrap();
        assert!(!authorized_device(&dir, &fp).unwrap());
        assert!(register_device(
            &dir,
            "family",
            revision,
            "second",
            &"b2".repeat(32),
            unix_seconds().unwrap() + 600
        )
        .is_err());
        change_password(&dir, "family", b"new-very-long-password").unwrap();
        assert!(!authorized_device(&dir, &fp).unwrap());
        let new_rev = authenticate_revision(&dir, "family", b"new-very-long-password")
            .unwrap()
            .unwrap();
        let fp2 = "b2".repeat(32);
        register_device(
            &dir,
            "family",
            new_rev,
            "phone-new",
            &fp2,
            unix_seconds().unwrap() + 600,
        )
        .unwrap();
        assert!(authorized_device(&dir, &fp2).unwrap());
        revoke_device(&dir, &fp2).unwrap();
        assert!(!authorized_device(&dir, &fp2).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn issued_cert_retry_is_idempotent_and_old_password_cannot_reenroll() {
        let dir = isolated();
        let pass = b"long-password-for-device-issuer";
        add(&dir, "family", pass).unwrap();
        let rev = authenticate_revision(&dir, "family", pass)
            .unwrap()
            .unwrap();
        let fp = "af".repeat(32);
        let csr = "9f".repeat(32);
        let expiry = unix_seconds().unwrap() + 3600;
        let cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let request = SignedDevice {
            username: "family",
            revision: rev,
            label: "android-1",
            csr_sha256: &csr,
            fingerprint: &fp,
            expires_at: expiry,
            certificate_pem: cert,
        };
        let first = register_signed_device(&dir, request).unwrap();
        let second = register_signed_device(
            &dir,
            SignedDevice {
                fingerprint: &"b1".repeat(32),
                ..request
            },
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(authorized_device(&dir, &fp).unwrap());
        assert!(register_signed_device(
            &dir,
            SignedDevice {
                csr_sha256: &"22".repeat(32),
                ..request
            }
        )
        .is_err());
        change_password(&dir, "family", b"even-more-secure-new-passphrase").unwrap();
        assert!(!authorized_device(&dir, &fp).unwrap());
        assert!(register_signed_device(
            &dir,
            SignedDevice {
                label: "android-2",
                ..request
            }
        )
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

}
