//! Opt-in application-level proof of device key possession.
//! This module never permits anonymous clients to access a packet stream.
//! TLS is still mandatory at the public edge. Tokens are random, one-time,
//! short lived, bounded, and consumed before signature verification.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509PurposeId, X509StoreContext, X509};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const CHALLENGE_BYTES: usize = 32;
const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_CHALLENGES: usize = 128;
const MAX_CERT_DER: usize = 8192;
const MAX_SIGNATURE: usize = 256;
pub const TUNNEL_PATH: &str = "/fedup-lab/v1/ip-tunnel";
pub const PROBE_PATH: &str = "/fedup-lab/v1/auth-check";

pub struct DeviceProof {
    ca: X509,
    challenges: Mutex<HashMap<[u8; CHALLENGE_BYTES], Instant>>,
}

impl DeviceProof {
    pub fn new(ca_pem: &[u8]) -> Result<Self> {
        let ca = X509::from_pem(ca_pem)?;
        // Sanity check: a misconfigured leaf must never become a root of trust.
        let mut builder = X509StoreBuilder::new()?;
        builder.add_cert(ca.clone())?;
        let _store = builder.build();
        Ok(Self {
            ca,
            challenges: Mutex::new(HashMap::new()),
        })
    }

    pub fn issue(&self) -> Result<String> {
        let now = Instant::now();
        let mut pending = self
            .challenges
            .lock()
            .map_err(|_| "challenge lock poisoned")?;
        pending.retain(|_, issued| now.duration_since(*issued) < CHALLENGE_TTL);
        if pending.len() >= MAX_CHALLENGES {
            return Err("too many outstanding challenges".into());
        }
        let mut nonce = [0u8; CHALLENGE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        if pending.insert(nonce, now).is_some() {
            return Err("challenge RNG collision".into());
        }
        Ok(URL_SAFE_NO_PAD.encode(nonce))
    }

    /// One-shot verification; success still needs live account revocation check.
    pub fn verify(
        &self,
        encoded_challenge: &str,
        encoded_cert: &str,
        encoded_signature: &str,
        method: &str,
        path: &str,
    ) -> Result<String> {
        if !matches!((method, path), ("GET", PROBE_PATH) | ("POST", TUNNEL_PATH))
            || encoded_challenge.len() != 43
            || encoded_cert.len() > 11000
            || encoded_signature.len() > 344
        {
            return Err("invalid device proof fields".into());
        }
        let raw_nonce = URL_SAFE_NO_PAD.decode(encoded_challenge)?;
        let nonce: [u8; CHALLENGE_BYTES] =
            raw_nonce.try_into().map_err(|_| "invalid challenge size")?;
        let issued = {
            let mut pending = self
                .challenges
                .lock()
                .map_err(|_| "challenge lock poisoned")?;
            pending
                .remove(&nonce)
                .ok_or("unknown or consumed challenge")?
        };
        if issued.elapsed() >= CHALLENGE_TTL {
            return Err("expired challenge".into());
        }
        let der = URL_SAFE_NO_PAD.decode(encoded_cert)?;
        let sig = URL_SAFE_NO_PAD.decode(encoded_signature)?;
        if der.is_empty() || der.len() > MAX_CERT_DER || sig.is_empty() || sig.len() > MAX_SIGNATURE
        {
            return Err("invalid device certificate or signature size".into());
        }
        let cert = X509::from_der(&der)?;
        let mut builder = X509StoreBuilder::new()?;
        builder.add_cert(self.ca.clone())?;
        builder.set_purpose(X509PurposeId::SSL_CLIENT)?;
        let store = builder.build();
        let chain = Stack::new()?;
        let mut ctx = X509StoreContext::new()?;
        if !ctx.init(&store, &cert, &chain, |ctx| ctx.verify_cert())? {
            return Err("device certificate failed trust verification".into());
        }
        let fingerprint = Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let signed = message(method, path, encoded_challenge, &fingerprint);
        let public = cert.public_key()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public)?;
        verifier.update(signed.as_bytes())?;
        if !verifier.verify(&sig)? {
            return Err("device key signature is invalid".into());
        }
        Ok(fingerprint)
    }
}

pub fn message(method: &str, path: &str, challenge: &str, fingerprint: &str) -> String {
    // Fixed ASCII canonical encoding. Keep this exactly aligned with Android.
    format!("FedUp-App-Proof-v1\n{method}\n{path}\n{challenge}\n{fingerprint}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use openssl::x509::{X509NameBuilder, X509};

    fn ca_and_device() -> (Vec<u8>, Vec<u8>, PKey<openssl::pkey::Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ca_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut ca_name = X509NameBuilder::new().unwrap();
        ca_name
            .append_entry_by_text("CN", "FedUp disposable proof CA")
            .unwrap();
        let ca_name = ca_name.build();
        let mut ca = X509::builder().unwrap();
        ca.set_version(2).unwrap();
        ca.set_subject_name(&ca_name).unwrap();
        ca.set_issuer_name(&ca_name).unwrap();
        ca.set_pubkey(&ca_key).unwrap();
        ca.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        ca.set_not_after(Asn1Time::days_from_now(2).unwrap().as_ref())
            .unwrap();
        let ca_ext = BasicConstraints::new().critical().ca().build().unwrap();
        ca.append_extension(ca_ext).unwrap();
        ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca = ca.build();

        let device_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut device_name = X509NameBuilder::new().unwrap();
        device_name
            .append_entry_by_text("CN", "fedup-test-device")
            .unwrap();
        let device_name = device_name.build();
        let mut leaf = X509::builder().unwrap();
        leaf.set_version(2).unwrap();
        leaf.set_subject_name(&device_name).unwrap();
        leaf.set_issuer_name(&ca_name).unwrap();
        leaf.set_pubkey(&device_key).unwrap();
        leaf.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        leaf.set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        let usage = ExtendedKeyUsage::new().client_auth().build().unwrap();
        leaf.append_extension(usage).unwrap();
        leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
        (
            ca.to_pem().unwrap(),
            leaf.build().to_der().unwrap(),
            device_key,
        )
    }

    #[test]
    fn valid_signed_challenge_is_one_time_and_method_scoped() {
        let (ca, cert, key) = ca_and_device();
        let state = DeviceProof::new(&ca).unwrap();
        let nonce = state.issue().unwrap();
        let fp = Sha256::digest(&cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let payload = message("POST", TUNNEL_PATH, &nonce, &fp);
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(payload.as_bytes()).unwrap();
        let signature = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap());
        let cert_b64 = URL_SAFE_NO_PAD.encode(&cert);
        assert_eq!(
            state
                .verify(&nonce, &cert_b64, &signature, "POST", TUNNEL_PATH)
                .unwrap(),
            fp
        );
        assert!(state
            .verify(&nonce, &cert_b64, &signature, "POST", TUNNEL_PATH)
            .is_err());
    }

    #[test]
    fn proof_for_one_method_cannot_authorize_another() {
        let (ca, cert, key) = ca_and_device();
        let state = DeviceProof::new(&ca).unwrap();
        let nonce = state.issue().unwrap();
        let fp = Sha256::digest(&cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer
            .update(message("GET", PROBE_PATH, &nonce, &fp).as_bytes())
            .unwrap();
        let signature = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap());
        assert!(state
            .verify(
                &nonce,
                &URL_SAFE_NO_PAD.encode(cert),
                &signature,
                "POST",
                TUNNEL_PATH
            )
            .is_err());
    }
}
