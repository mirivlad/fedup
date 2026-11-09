//! FedUp netguard: a separate privileged nftables policy helper.
//! ONLY supports an isolated Linux network namespace in this experimental stage.
//! Policy lives in the kernel after this program and the TUN process exit.
//! No system-wide routing, DNS, NAT, or kill switch is installed.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const TABLE: &str = "fedup_lab_guard";
const CHAIN: &str = "output";
const MAX_CONFIG: u64 = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u8,
    tun: String,
    protected_ipv4: Vec<Ipv4Addr>,
    protected_ipv6: Vec<Ipv6Addr>,
    block_plain_dns: bool,
}

fn isolated() -> Result<()> {
    if fs::read_link("/proc/self/ns/net")? == fs::read_link("/proc/1/ns/net")? {
        return Err("refusing initial Linux network namespace: laboratory only".into());
    }
    Ok(())
}

fn valid_interface(name: &str) -> bool {
    (3..=15).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl Policy {
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err("only netguard policy version 1 is supported".into());
        }
        if !valid_interface(&self.tun) {
            return Err("invalid TUN interface name".into());
        }
        // This helper is intentionally restricted to exact lab hosts. No CIDR
        // ranges, default routes, or arbitrary Internet destinations are allowed.
        if self.protected_ipv4.is_empty() || self.protected_ipv4.len() > 16 {
            return Err("policy must have 1-16 protected IPv4 hosts".into());
        }
        if self.protected_ipv6.is_empty() || self.protected_ipv6.len() > 16 {
            return Err("policy must have 1-16 protected IPv6 hosts".into());
        }
        if !self.block_plain_dns {
            return Err("unencrypted DNS outside TUN must be blocked".into());
        }
        let mut v4 = BTreeSet::new();
        for addr in &self.protected_ipv4 {
            if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() {
                return Err("invalid protected IPv4 host".into());
            }
            if !v4.insert(*addr) {
                return Err("duplicate protected IPv4 host".into());
            }
        }
        let mut v6 = BTreeSet::new();
        for addr in &self.protected_ipv6 {
            if addr.is_unspecified() || addr.is_multicast() {
                return Err("invalid protected IPv6 host".into());
            }
            if !v6.insert(*addr) {
                return Err("duplicate protected IPv6 host".into());
            }
        }
        Ok(())
    }

    fn rules(&self) -> Vec<String> {
        let mut rules = Vec::new();
        for host in &self.protected_ipv4 {
            rules.push(format!(
                "ip daddr {host} oifname != \"{}\" counter drop",
                self.tun
            ));
        }
        for host in &self.protected_ipv6 {
            rules.push(format!(
                "ip6 daddr {host} oifname != \"{}\" counter drop",
                self.tun
            ));
        }
        if self.block_plain_dns {
            rules.push(format!(
                "udp dport 53 oifname != \"{}\" counter drop",
                self.tun
            ));
            rules.push(format!(
                "tcp dport 53 oifname != \"{}\" counter drop",
                self.tun
            ));
        }
        rules
    }

    fn install_batch(&self) -> String {
        let mut script = format!(
            "create table inet {TABLE}\n\
             add chain inet {TABLE} {CHAIN} {{ type filter hook output priority -50; policy accept; }}\n"
        );
        for rule in self.rules() {
            script.push_str(&format!("add rule inet {TABLE} {CHAIN} {rule}\n"));
        }
        script
    }
}

fn load(path: &Path) -> Result<Policy> {
    if fs::metadata(path)?.len() > MAX_CONFIG {
        return Err("netguard policy file exceeds limit".into());
    }
    let content = fs::read(path)?;
    if content.len() as u64 > MAX_CONFIG {
        return Err("netguard policy file exceeds limit".into());
    }
    let policy: Policy = serde_json::from_slice(&content)?;
    policy.validate()?;
    Ok(policy)
}

fn run_nft(args: &[&str], script: Option<&str>) -> Result<std::process::Output> {
    let mut command = Command::new("nft");
    command.args(args).stdin(if script.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(contents) = script {
        child
            .stdin
            .take()
            .ok_or("nft did not create stdin")?
            .write_all(contents.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

fn nft_ok(args: &[&str], script: Option<&str>) -> Result<String> {
    let output = run_nft(args, script)?;
    if !output.status.success() {
        return Err(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Strip only dynamic packet/byte counts. Do not silently ignore additional
/// accept, jump, or altered-match operations when inspecting the policy.
fn without_counters(line: &str) -> Result<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < parts.len() {
        if parts[index] == "counter"
            && index + 4 < parts.len()
            && parts[index + 1] == "packets"
            && parts[index + 3] == "bytes"
            && parts[index + 2].parse::<u64>().is_ok()
            && parts[index + 4].parse::<u64>().is_ok()
        {
            out.push("counter");
            index += 5;
        } else {
            out.push(parts[index]);
            index += 1;
        }
    }
    if !out.contains(&"drop") {
        return Err("observed policy rule has no drop verdict".into());
    }
    Ok(out.join(" "))
}

fn inspect(output: &str, policy: &Policy) -> Result<()> {
    let mut table = false;
    let mut chain = false;
    let mut declaration = false;
    let mut seen_rules = Vec::new();
    let mut sections = 0;
    for row in output.lines() {
        let value = row.trim();
        if value.is_empty() {
            continue;
        }
        if value == format!("table inet {TABLE} {{") {
            if table {
                return Err("multiple netguard tables".into());
            }
            table = true;
        } else if value == format!("chain {CHAIN} {{") {
            if chain {
                return Err("multiple netguard chains".into());
            }
            chain = true;
            sections += 1;
        } else if value.starts_with("type filter hook output priority ") {
            if value != "type filter hook output priority -50; policy accept;" {
                return Err("unexpected netguard chain hook or priority".into());
            }
            declaration = true;
        } else if value == "}" {
            // Both the chain and table close with a brace.
        } else if value.starts_with('#') {
            // nft-generated comments are not part of rule semantics.
        } else {
            seen_rules.push(without_counters(value)?);
        }
    }
    if !table || !chain || !declaration || sections != 1 {
        return Err("netguard table or output hook is missing".into());
    }
    let mut expected = policy.rules();
    // nft inserts a meta l4proto guard on protocol-specific rules.
    for line in &mut seen_rules {
        if let Some(rest) = line.strip_prefix("meta l4proto ") {
            if rest.starts_with("udp ") || rest.starts_with("tcp ") {
                *line = rest.to_owned();
            }
        }
    }
    expected.sort_unstable();
    seen_rules.sort_unstable();
    if seen_rules != expected {
        return Err(format!(
            "netguard rules differ from configured policy: expected {expected:?}, actual {seen_rules:?}"
        )
        .into());
    }
    Ok(())
}

fn verify(policy: &Policy) -> Result<()> {
    let shown = nft_ok(&["list", "table", "inet", TABLE], None)?;
    inspect(&shown, policy)
}

fn install(policy: &Policy) -> Result<()> {
    // Never replace or flush an existing table; another process may own it.
    let old = run_nft(&["list", "table", "inet", TABLE], None)?;
    if old.status.success() {
        return Err("netguard table already exists; use 'verify', never overwrite".into());
    }
    // nft transaction is atomic; 'create table' fails on concurrent installs.
    nft_ok(&["-f", "-"], Some(&policy.install_batch()))?;
    verify(policy)?;
    println!("FedUp laboratory netguard policy installed (survives VPN process exit)");
    Ok(())
}

fn remove(policy: &Policy) -> Result<()> {
    // Explicit operator operation, and only if exact rule integrity is proven.
    verify(policy)?;
    nft_ok(&["delete", "table", "inet", TABLE], None)?;
    println!("FedUp laboratory netguard removed by explicit operator request");
    Ok(())
}

fn usage() {
    eprintln!(
        "Lab-only netguard; MUST run inside an isolated Linux network namespace:\n\
         fedup-netguard plan <policy.json>\n\
         fedup-netguard install <policy.json>\n\
         fedup-netguard verify <policy.json>\n\
         fedup-netguard remove <policy.json> --confirm-lab-remove\n\
         No changes to host routes, firewall or DNS are authorized."
    );
}

fn main() {
    if let Err(err) = run() {
        eprintln!("fedup-netguard: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, action, path] if action == "plan" => {
            let policy = load(Path::new(path))?;
            println!("{}", policy.install_batch());
            Ok(())
        }
        [_, action, path] if action == "install" || action == "verify" => {
            isolated()?;
            let policy = load(Path::new(path))?;
            if action == "install" {
                install(&policy)
            } else {
                verify(&policy)?;
                println!("FedUp laboratory netguard policy integrity: PASS");
                Ok(())
            }
        }
        [_, action, path, confirmation]
            if action == "remove" && confirmation == "--confirm-lab-remove" =>
        {
            isolated()?;
            remove(&load(Path::new(path))?)
        }
        _ => {
            usage();
            Err("invalid netguard operation".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            version: 1,
            tun: "futclient".to_string(),
            protected_ipv4: vec!["10.88.0.10".parse().unwrap()],
            protected_ipv6: vec!["fd42:fed1::10".parse().unwrap()],
            block_plain_dns: true,
        }
    }

    #[test]
    fn generates_an_atomic_create_only_batch() {
        let script = policy().install_batch();
        assert!(script.starts_with("create table inet fedup_lab_guard\n"));
        assert!(script.contains("ip daddr 10.88.0.10 oifname != \"futclient\" counter drop"));
        assert!(script.contains("ip6 daddr fd42:fed1::10 oifname != \"futclient\" counter drop"));
        assert!(script.contains("udp dport 53 oifname != \"futclient\" counter drop"));
        assert!(!script.contains("flush ruleset"));
        assert!(!script.contains("delete table"));
    }

    #[test]
    fn never_accepts_injected_interface() {
        let mut config = policy();
        config.tun = "tun0\"; accept;".to_owned();
        assert!(config.validate().is_err());
        config.tun = "futclient".to_owned();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_and_missing_family_and_plain_dns_leak() {
        let mut config = policy();
        config.protected_ipv4.push(config.protected_ipv4[0]);
        assert!(config.validate().is_err());
        config = policy();
        config.protected_ipv6.clear();
        assert!(config.validate().is_err());
        config = policy();
        config.block_plain_dns = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn strict_json_rejects_unexpected_fields_and_cidrs() {
        let json = r#"{"version":1,"tun":"futclient","protected_ipv4":["10.88.0.0/24"],"protected_ipv6":["fd42:fed1::10"],"block_plain_dns":true}"#;
        assert!(serde_json::from_str::<Policy>(json).is_err());
        let json = r#"{"version":1,"tun":"futclient","protected_ipv4":["10.88.0.10"],"protected_ipv6":["fd42:fed1::10"],"block_plain_dns":true,"allow_cleartext":true}"#;
        assert!(serde_json::from_str::<Policy>(json).is_err());
    }

    #[test]
    fn detects_ruleset_drift_without_ignoring_counters() {
        let text = r#"table inet fedup_lab_guard {
            chain output {
                type filter hook output priority -50; policy accept;
                ip daddr 10.88.0.10 oifname != "futclient" counter packets 5 bytes 720 drop
                ip6 daddr fd42:fed1::10 oifname != "futclient" counter packets 3 bytes 128 drop
                udp dport 53 oifname != "futclient" counter packets 0 bytes 0 drop
                tcp dport 53 oifname != "futclient" counter packets 0 bytes 0 drop
            }
        }"#;
        assert!(inspect(text, &policy()).is_ok());
        let altered = text.replace(
            "counter packets 5 bytes 720 drop",
            "counter packets 5 bytes 720 accept",
        );
        assert!(inspect(&altered, &policy()).is_err());
        let altered = text.replace("10.88.0.10", "10.88.0.11");
        assert!(inspect(&altered, &policy()).is_err());
    }
}
