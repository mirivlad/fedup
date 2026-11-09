//! Explicitly opt-in, laboratory-only online signer.
//! A real deployment MUST replace this with a delegated, independently
//! protected signer. Never expose the offline/root CA key to the HTTP service.

use rand::{rngs::OsRng, RngCore};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls_pemfile::certs;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use time::OffsetDateTime;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub struct LabIssuer {
    ca_pem: String,
    ca_key: Zeroizing<String>,
    ca_sha256: String,
    server_name: String,
}

#[derive(Serialize)]
pub struct IssuedDevice {
    pub certificate_pem: String,
    pub ca_pem: String,
    pub server_name: String,
    pub ca_sha256: String,
    pub fingerprint_sha256: String,
    pub expires_at: i64,
}

#[derive(Serialize)]
pub struct PublicConfig {
    pub server_name: String,
    pub ca_pem: String,
    pub ca_sha256: String,
}

fn one_certificate(pem: &str) -> Result<Vec<u8>> {
    let all = certs(&mut BufReader::new(pem.as_bytes())).collect::<std::io::Result<Vec<_>>>()?;
    if all.len() != 1 {
        return Err("issuer must have exactly one CA certificate".into());
    }
    Ok(all[0].as_ref().to_vec())
}

fn safe_read(path: &Path, secret: bool) -> Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 32 * 1024 {
        return Err("CA must be a non-symlink ordinary file <= 32 KiB".into());
    }
    if secret && meta.permissions().mode() & 0o077 != 0 {
        return Err("online lab CA key file MUST be private (0600)".into());
    }
    Ok(fs::read_to_string(path)?)
}

impl LabIssuer {
    pub fn load(cert: &Path, key: &Path, server_name: &str) -> Result<Self> {
        if server_name.is_empty()
            || server_name.len() > 253
            || !server_name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        {
            return Err("invalid server TLS hostname".into());
        }
        let ca_pem = safe_read(cert, false)?;
        let ca_key = Zeroizing::new(safe_read(key, true)?);
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, KeyPair::from_pem(&ca_key)?)?;
        drop(issuer);
        let ca_sha256 = hex::encode(Sha256::digest(one_certificate(&ca_pem)?));
        Ok(Self {
            ca_pem,
            ca_key,
            ca_sha256,
            server_name: server_name.to_string(),
        })
    }

    pub fn public_config(&self) -> PublicConfig {
        PublicConfig {
            server_name: self.server_name.clone(),
            ca_pem: self.ca_pem.clone(),
            ca_sha256: self.ca_sha256.clone(),
        }
    }

    pub fn issue(&self, csr_pem: &str, device: &str) -> Result<IssuedDevice> {
        if csr_pem.len() > 8192 || csr_pem.is_empty() {
            return Err("invalid or oversized device CSR".into());
        }
        if device.is_empty()
            || device.len() > 48
            || !device
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        {
            return Err("invalid device label".into());
        }
        // rcgen verifies the CSR's proof of possession. Never copy untrusted
        // CSR subject names or requested extensions into the signed cert.
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_pem, KeyPair::from_pem(&self.ca_key)?)?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, format!("fedup-{device}"));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(7);
        let mut serial = [0u8; 16];
        OsRng.fill_bytes(&mut serial);
        serial[0] = (serial[0] & 0x7f) | 1;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let expires_at = params.not_after.unix_timestamp();
        let signed = params.signed_by(&csr.public_key, &issuer)?;
        let certificate_pem = signed.pem();
        let fingerprint_sha256 = hex::encode(Sha256::digest(one_certificate(&certificate_pem)?));
        Ok(IssuedDevice {
            certificate_pem,
            ca_pem: self.ca_pem.clone(),
            server_name: self.server_name.clone(),
            ca_sha256: self.ca_sha256.clone(),
            fingerprint_sha256,
            expires_at,
        })
    }
}
