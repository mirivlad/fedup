//! Client-side identity for the experimental FedUp transport.
//! Only encrypted PKCS#8 private keys are written to disk; no plaintext fallback.
//! Desktop/Linux prototype, NOT an Android Keystore or Windows CNG implementation.

use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509NameBuilder, X509PurposeId, X509Req, X509StoreContext, X509};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub type IdentityResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const FILE_LIMIT: u64 = 64 * 1024;
const KEY_LIMIT: u64 = 16 * 1024;
const INVITE_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    version: u32,
    id: String,
    token: String,
    device: String,
    expires_at: i64,
    server_name: String,
    ca_sha256: String,
    ca_pem: String,
}

#[derive(Serialize)]
struct EnrollmentRequest<'a> {
    version: u32,
    id: &'a str,
    token: &'a str,
    device: &'a str,
    server_name: &'a str,
    ca_sha256: &'a str,
    csr_pem: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceMetadata {
    version: u32,
    id: String,
    device: String,
    server_name: String,
    ca_sha256: String,
}

fn valid_device(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn now() -> IdentityResult<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

pub fn read_limited(path: &Path, max_size: u64) -> IdentityResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_size {
        return Err("input must be an ordinary non-symlink file within size limit".into());
    }
    let mut contents = Vec::new();
    File::open(path)?
        .take(max_size + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > max_size {
        return Err("input exceeds configured size limit".into());
    }
    Ok(contents)
}

fn create_file(path: &Path, contents: &[u8]) -> IdentityResult<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn ca_hash(ca_pem: &[u8]) -> IdentityResult<String> {
    let ca = X509::from_pem(ca_pem)?;
    Ok(hex_digest(&ca.to_der()?))
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn check_invitation(inv: &Invitation) -> IdentityResult<()> {
    if inv.version != INVITE_VERSION
        || !valid_hex(&inv.id, 16)
        || !valid_hex(&inv.token, 32)
        || !valid_device(&inv.device)
        || !valid_hex(&inv.ca_sha256, 32)
        || inv.server_name.is_empty()
        || inv.server_name.len() > 253
        || !inv
            .server_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || ca_hash(inv.ca_pem.as_bytes())? != inv.ca_sha256
        || now()? >= inv.expires_at
    {
        return Err("invitation is invalid or expired; verify its trusted source".into());
    }
    Ok(())
}

/// Generate a unique P-256 key and signed CSR; only encrypted PKCS#8 leaves memory.
fn generate_key_and_csr(device: &str, password: &[u8]) -> IdentityResult<(Vec<u8>, Vec<u8>)> {
    if password.len() < 16 || password.len() > 1024 {
        return Err("passphrase must have 16-1024 UTF-8 bytes".into());
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, &format!("fedup-{device}"))?;
    let mut csr = X509Req::builder()?;
    csr.set_version(0)?;
    csr.set_subject_name(&name.build())?;
    csr.set_pubkey(&key)?;
    csr.sign(&key, MessageDigest::sha256())?;
    let encrypted = key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password)?;
    if !encrypted.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err("OpenSSL did not return encrypted PKCS#8".into());
    }
    Ok((encrypted, csr.build().to_pem()?))
}

/// Construct an enrollment request while keeping the private key in a 0700 directory.
/// The request contains a *bearer token*: transmit it over a trusted channel.
pub fn initialize_from_invitation(
    invitation_path: &Path,
    device_dir: &Path,
    request_output: &Path,
    password: &[u8],
) -> IdentityResult<()> {
    let inv: Invitation = serde_json::from_slice(&read_limited(invitation_path, FILE_LIMIT)?)?;
    check_invitation(&inv)?;
    let (encrypted, csr) = generate_key_and_csr(&inv.device, password)?;
    let csr_text = std::str::from_utf8(&csr)?;
    let request = EnrollmentRequest {
        version: INVITE_VERSION,
        id: &inv.id,
        token: &inv.token,
        device: &inv.device,
        server_name: &inv.server_name,
        ca_sha256: &inv.ca_sha256,
        csr_pem: csr_text,
    };
    let request_bytes = serde_json::to_vec_pretty(&request)?;
    let metadata = DeviceMetadata {
        version: INVITE_VERSION,
        id: inv.id,
        device: inv.device,
        server_name: inv.server_name,
        ca_sha256: inv.ca_sha256,
    };

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(device_dir)?;
    let result: IdentityResult<()> = (|| {
        create_file(&device_dir.join("client-key.enc.pem"), &encrypted)?;
        create_file(&device_dir.join("client.csr.pem"), &csr)?;
        create_file(&device_dir.join("ca.pem"), inv.ca_pem.as_bytes())?;
        create_file(
            &device_dir.join("device.json"),
            &serde_json::to_vec_pretty(&metadata)?,
        )?;
        create_file(request_output, &request_bytes)?;
        Ok(())
    })();
    if result.is_err() {
        // Only remove the directory we just created; the request file may be
        // outside this directory. create_file cleans up partial writes itself.
        let _ = fs::remove_dir_all(device_dir);
    }
    result
}

/// Never accept a plaintext private key even when a legacy file exists.
/// Caller receives only in-memory, zeroized-on-drop unencrypted DER.
pub fn decrypt_pkcs8(path: &Path, password: &[u8]) -> IdentityResult<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("private key must be readable only by its owner (mode 0600)".into());
    }
    let contents = read_limited(path, KEY_LIMIT)?;
    if !contents.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err("unencrypted private keys are forbidden in the secure client mode".into());
    }
    let private = PKey::private_key_from_pem_passphrase(&contents, password)?;
    Ok(Zeroizing::new(private.private_key_to_pkcs8()?))
}

fn load_private(path: &Path, password: &[u8]) -> IdentityResult<PKey<Private>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("private key must be mode 0600".into());
    }
    let contents = read_limited(path, KEY_LIMIT)?;
    if !contents.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err("plaintext private key refused".into());
    }
    Ok(PKey::private_key_from_pem_passphrase(&contents, password)?)
}

fn private_directory(dir: &Path) -> IdentityResult<()> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err("device directory must be private (mode 0700)".into());
    }
    Ok(())
}

/// Validate CA chain, expiration and match to the locally held private key.
pub fn import_certificate(
    device_dir: &Path,
    received_cert: &Path,
    password: &[u8],
) -> IdentityResult<()> {
    private_directory(device_dir)?;
    let metadata: DeviceMetadata =
        serde_json::from_slice(&read_limited(&device_dir.join("device.json"), FILE_LIMIT)?)?;
    if metadata.version != INVITE_VERSION
        || !valid_device(&metadata.device)
        || !valid_hex(&metadata.ca_sha256, 32)
    {
        return Err("invalid device metadata".into());
    }
    let ca_pem = read_limited(&device_dir.join("ca.pem"), FILE_LIMIT)?;
    if ca_hash(&ca_pem)? != metadata.ca_sha256 {
        return Err("CA pin mismatch in local device identity".into());
    }
    let ca = X509::from_pem(&ca_pem)?;
    let cert = X509::from_pem(&read_limited(received_cert, FILE_LIMIT)?)?;
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(ca)?;
    store_builder.set_purpose(X509PurposeId::SSL_CLIENT)?;
    let store = store_builder.build();
    let chain = Stack::new()?;
    let mut ctx = X509StoreContext::new()?;
    if !ctx.init(&store, &cert, &chain, |c| c.verify_cert())? {
        return Err("certificate chain validation failed".into());
    }
    let common_name = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or("client certificate is missing its subject CN")?
        .data()
        .to_string();
    if common_name != format!("fedup-{}", metadata.device) {
        return Err("client certificate identity does not match the invitation device".into());
    }
    let private = load_private(&device_dir.join("client-key.enc.pem"), password)?;
    if !cert.public_key()?.public_eq(&private) {
        return Err("certificate does not match the local device private key".into());
    }
    create_file(&device_dir.join("client.pem"), &cert.to_pem()?)
}

/// Resolve connection parameters from the imported identity and pinned CA.
#[derive(Debug)]
pub struct DeviceConnection {
    pub server_name: String,
    pub ca_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
    pub encrypted_key_path: std::path::PathBuf,
}

pub fn device_connection(device_dir: &Path) -> IdentityResult<DeviceConnection> {
    private_directory(device_dir)?;
    let metadata: DeviceMetadata =
        serde_json::from_slice(&read_limited(&device_dir.join("device.json"), FILE_LIMIT)?)?;
    if metadata.version != INVITE_VERSION
        || !valid_device(&metadata.device)
        || metadata.server_name.is_empty()
        || metadata.server_name.len() > 253
        || !metadata
            .server_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || !valid_hex(&metadata.ca_sha256, 32)
    {
        return Err("device connection metadata is invalid".into());
    }
    let ca_path = device_dir.join("ca.pem");
    let cert_path = device_dir.join("client.pem");
    let key_path = device_dir.join("client-key.enc.pem");
    if ca_hash(&read_limited(&ca_path, FILE_LIMIT)?)? != metadata.ca_sha256 {
        return Err("device CA identity has changed since enrollment".into());
    }
    // Loading validates the type/size before either endpoint is used.
    X509::from_pem(&read_limited(&cert_path, FILE_LIMIT)?)?;
    let _ = read_limited(&key_path, KEY_LIMIT)?;
    Ok(DeviceConnection {
        server_name: metadata.server_name,
        ca_path,
        cert_path,
        encrypted_key_path: key_path,
    })
}

/// For headless automated TESTS only, read the password from stdin.
/// Interactive usage reads directly from a terminal without echo.
pub fn read_password(confirm: bool, password_stdin: bool) -> IdentityResult<Zeroizing<String>> {
    let first = if password_stdin {
        let mut input = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut input)?;
        while input.ends_with('\n') || input.ends_with('\r') {
            input.pop();
        }
        input
    } else {
        Zeroizing::new(rpassword::prompt_password(
            "Device private-key passphrase: ",
        )?)
    };
    if first.len() < 16 || first.len() > 1024 {
        return Err("passphrase must contain 16-1024 UTF-8 bytes".into());
    }
    if confirm {
        let second = if password_stdin {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            Zeroizing::new(input.trim_end_matches(['\n', '\r']).to_owned())
        } else {
            Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?)
        };
        if *first != *second {
            return Err("passphrases do not match".into());
        }
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn encrypted_key_is_only_usable_with_correct_passphrase() {
        let (encrypted, csr) =
            generate_key_and_csr("test-device", b"long-test-only-password").unwrap();
        assert!(encrypted.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(csr.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----"));
        let dir = tempdir().unwrap();
        let key = dir.path().join("key.pem");
        create_file(&key, &encrypted).unwrap();
        let der = decrypt_pkcs8(&key, b"long-test-only-password").unwrap();
        assert!(!der.is_empty());
        assert!(decrypt_pkcs8(&key, b"wrong-test-passphrase").is_err());
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o077, 0);
    }

    #[test]
    fn no_plaintext_or_symlink_key_fallback() {
        let dir = tempdir().unwrap();
        let key = dir.path().join("plaintext");
        create_file(&key, b"-----BEGIN PRIVATE KEY-----\nTEST\n").unwrap();
        assert!(decrypt_pkcs8(&key, b"long-test-only-password").is_err());
        let link = dir.path().join("symlink");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(decrypt_pkcs8(&link, b"long-test-only-password").is_err());
    }

    #[test]
    fn bad_passphrase_and_device_name_refused() {
        assert!(generate_key_and_csr("phone", b"short").is_err());
        assert!(!valid_device("../escaped"));
        assert!(!valid_device("bad space"));
        assert!(valid_device("phone-2"));
    }
}
