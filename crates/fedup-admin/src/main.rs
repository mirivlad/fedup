//! SSH-first administrator for the experimental FedUp certificate allowlist.
//! This is not a CA, enrollment service or finished VPN administration system.
use fs2::FileExt;
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

type AdminResult<T> = Result<T, Box<dyn Error>>;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_DEVICES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Device {
    name: Option<String>,
    fingerprint: String,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_inventory(content: &str) -> AdminResult<Vec<Device>> {
    if content.len() as u64 > MAX_FILE_BYTES {
        return Err("authorization file exceeds size limit".into());
    }
    let mut devices = Vec::new();
    let mut seen_fingerprints = HashSet::new();
    let mut seen_names = HashSet::new();
    let mut pending_name: Option<String> = None;
    for (line_number, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("# device:") {
            if pending_name.is_some() {
                return Err(format!("line {}: consecutive device labels", line_number + 1).into());
            }
            let name = value.trim();
            if !valid_name(name) {
                return Err(format!("line {}: invalid device name", line_number + 1).into());
            }
            pending_name = Some(name.to_string());
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if !valid_fingerprint(line) {
            return Err(
                format!("line {}: invalid certificate fingerprint", line_number + 1).into(),
            );
        }
        if devices.len() >= MAX_DEVICES {
            return Err("too many authorized devices".into());
        }
        let fp = line.to_ascii_lowercase();
        if !seen_fingerprints.insert(fp.clone()) {
            return Err(format!("line {}: duplicate fingerprint", line_number + 1).into());
        }
        if let Some(ref name) = pending_name {
            if !seen_names.insert(name.clone()) {
                return Err(format!("line {}: duplicate device name", line_number + 1).into());
            }
        }
        devices.push(Device {
            name: pending_name.take(),
            fingerprint: fp,
        });
    }
    if pending_name.is_some() {
        return Err("device label without a certificate fingerprint".into());
    }
    Ok(devices)
}

fn render_inventory(devices: &[Device]) -> String {
    let mut entries = devices.to_vec();
    entries.sort_by(|a, b| {
        a.name
            .as_deref()
            .unwrap_or("")
            .cmp(b.name.as_deref().unwrap_or(""))
            .then(a.fingerprint.cmp(&b.fingerprint))
    });
    let mut out = String::from("# FedUp authorized client certificates v1\n");
    for device in entries {
        if let Some(name) = device.name {
            out.push_str(&format!("# device: {name}\n"));
        }
        out.push_str(&device.fingerprint);
        out.push('\n');
    }
    out
}

fn read_inventory(path: &Path) -> AdminResult<Vec<Device>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("authorization list must be an ordinary file, not a symlink".into());
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err("authorization file exceeds size limit".into());
    }
    let text = fs::read_to_string(path)?;
    parse_inventory(&text)
}

fn exclusive_lock(path: &Path) -> AdminResult<File> {
    let name = path
        .file_name()
        .ok_or("authorization path has no file name")?;
    let lock_name = format!("{}.lock", name.to_string_lossy());
    let lock_path = path.with_file_name(lock_name);
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("authorization lock path must be an ordinary file".into());
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&lock_path)?;
    file.lock_exclusive()?;
    Ok(file)
}

fn atomic_replace(path: &Path, devices: &[Device]) -> AdminResult<()> {
    let dir = path
        .parent()
        .ok_or("authorization file needs a parent directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(render_inventory(devices).as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn initialize(path: &Path) -> AdminResult<()> {
    let _lock = exclusive_lock(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(render_inventory(&[]).as_bytes())?;
    file.sync_all()?;
    let dir = path
        .parent()
        .ok_or("authorization file needs a parent directory")?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn with_inventory_mutation<F>(path: &Path, change: F) -> AdminResult<()>
where
    F: FnOnce(&mut Vec<Device>) -> AdminResult<()>,
{
    let _lock = exclusive_lock(path)?;
    let mut devices = read_inventory(path)?;
    change(&mut devices)?;
    if devices.len() > MAX_DEVICES {
        return Err("too many devices".into());
    }
    atomic_replace(path, &devices)
}

fn add_device(path: &Path, name: &str, fp: &str) -> AdminResult<()> {
    if !valid_name(name) {
        return Err(
            "device name must be 1-48 ASCII letters, digits, dots, hyphens or underscores".into(),
        );
    }
    if !valid_fingerprint(fp) {
        return Err("invalid certificate fingerprint".into());
    }
    let fp = fp.to_ascii_lowercase();
    with_inventory_mutation(path, |devices| {
        if devices.iter().any(|d| d.name.as_deref() == Some(name)) {
            return Err("device name already exists".into());
        }
        if devices.iter().any(|d| d.fingerprint == fp) {
            return Err("certificate fingerprint already exists".into());
        }
        devices.push(Device {
            name: Some(name.to_string()),
            fingerprint: fp,
        });
        Ok(())
    })
}

fn revoke_device(path: &Path, selector: &str) -> AdminResult<()> {
    with_inventory_mutation(path, |devices| {
        let before = devices.len();
        devices.retain(|d| {
            d.name.as_deref() != Some(selector)
                && !(valid_fingerprint(selector) && d.fingerprint.eq_ignore_ascii_case(selector))
        });
        if devices.len() == before {
            return Err("device not found; no changes written".into());
        }
        Ok(())
    })
}

fn certificate_fingerprint(path: &Path) -> AdminResult<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let cert = certs(&mut reader)
        .next()
        .ok_or("certificate file contains no certificates")??;
    let digest = Sha256::digest(cert.as_ref());
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn usage() {
    eprintln!(
        "FedUp experimental device administration (Linux, local SSH)\n\
         fedup-admin init <allowlist.txt>\n\
         fedup-admin list <allowlist.txt>\n\
         fedup-admin fingerprint <client-cert.pem>\n\
         fedup-admin add <allowlist.txt> <device-name> <client-cert.pem>\n\
         fedup-admin revoke <allowlist.txt> <device-name-or-fingerprint>\n\
         WARNING: adding a fingerprint does not sign or issue a certificate."
    );
}

fn run() -> AdminResult<()> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, action, path] if action == "init" => {
            initialize(Path::new(path))?;
            println!("Initialized device allowlist: {path}");
        }
        [_, action, path] if action == "list" => {
            for device in read_inventory(Path::new(path))? {
                println!(
                    "{}\t{}",
                    device.name.as_deref().unwrap_or("(legacy)"),
                    device.fingerprint
                );
            }
        }
        [_, action, certificate] if action == "fingerprint" => {
            println!("{}", certificate_fingerprint(Path::new(certificate))?);
        }
        [_, action, path, name, certificate] if action == "add" => {
            let fp = certificate_fingerprint(Path::new(certificate))?;
            add_device(Path::new(path), name, &fp)?;
            println!("Authorized {name}: {fp}");
        }
        [_, action, path, selector] if action == "revoke" => {
            revoke_device(Path::new(path), selector)?;
            println!("Revoked {selector}");
        }
        _ => {
            usage();
            return Err("invalid command-line arguments".into());
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fedup-admin: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn parses_named_and_legacy_records() {
        let data = format!("# comment\n# device: phone\n{}\n\n{}\n", fp('A'), fp('b'));
        let devices = parse_inventory(&data).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].name.as_deref(), Some("phone"));
        assert_eq!(devices[0].fingerprint, fp('a'));
        assert_eq!(devices[1].name, None);
        let mut round_tripped = parse_inventory(&render_inventory(&devices)).unwrap();
        let mut expected = devices;
        round_tripped.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        expected.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        assert_eq!(round_tripped, expected);
    }

    #[test]
    fn rejects_invalid_or_duplicate_entries() {
        let cases = [
            "# device: bad space\n",
            "# device: orphan\n",
            &format!("{}\n{}\n", fp('a'), fp('A')),
            &format!("# device: x\n{}\n# device: x\n{}\n", fp('a'), fp('b')),
            "not-a-fingerprint\n",
            "# device: first\n# device: second\n",
        ];
        for case in cases {
            assert!(
                parse_inventory(case).is_err(),
                "accepted malformed allowlist"
            );
        }
    }

    #[test]
    fn administrative_update_is_atomic_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.txt");
        initialize(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        add_device(&path, "phone", &fp('a')).unwrap();
        add_device(&path, "laptop", &fp('b')).unwrap();
        assert!(add_device(&path, "phone", &fp('c')).is_err());
        assert!(add_device(&path, "another", &fp('a')).is_err());
        assert_eq!(read_inventory(&path).unwrap().len(), 2);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        revoke_device(&path, "phone").unwrap();
        assert_eq!(read_inventory(&path).unwrap().len(), 1);
        assert!(revoke_device(&path, "phone").is_err());
        assert_eq!(read_inventory(&path).unwrap().len(), 1);
    }

    #[test]
    fn malformed_file_is_not_replaced_by_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.txt");
        fs::write(&path, "invalid record\n").unwrap();
        let old = fs::read(&path).unwrap();
        assert!(add_device(&path, "phone", &fp('a')).is_err());
        assert_eq!(fs::read(&path).unwrap(), old);
    }

    #[test]
    fn refuses_symlink_authorization_path() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let linked = dir.path().join("linked");
        initialize(&original).unwrap();
        std::os::unix::fs::symlink(&original, &linked).unwrap();
        assert!(add_device(&linked, "phone", &fp('a')).is_err());
    }

    #[test]
    fn concurrent_updates_do_not_lose_devices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.txt");
        initialize(&path).unwrap();
        std::thread::scope(|scope| {
            for (i, ch) in ['a', 'b', 'c', 'd'].into_iter().enumerate() {
                let path = &path;
                scope.spawn(move || {
                    add_device(path, &format!("device{i}"), &fp(ch)).unwrap();
                });
            }
        });
        assert_eq!(read_inventory(&path).unwrap().len(), 4);
    }

    #[test]
    fn invalid_name_and_init_overwrite_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.txt");
        initialize(&path).unwrap();
        assert!(initialize(&path).is_err());
        for name in ["", "bad space", "../oops", "x/y"] {
            assert!(add_device(&path, name, &fp('a')).is_err());
        }
        assert!(read_inventory(&path).unwrap().is_empty());
    }
}
