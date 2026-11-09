//! Linux CLI for client-side secure FedUp device identity.
use fedup_identity::{import_certificate, initialize_from_invitation, read_password};
use std::env;
use std::error::Error;
use std::path::Path;

fn usage() {
    eprintln!(
        "FedUp experimental Linux device identity:\n\
         fedup-device request <invitation.json> <new-private-device-dir> <request.json> [--passphrase-stdin]\n\
         fedup-device import <private-device-dir> <signed-client-cert.pem> [--passphrase-stdin]\n\
         Passphrase is normally prompted without echo; --passphrase-stdin is for disposable automated tests.\n\
         No unencrypted key files are ever created. No OS keyring integration yet."
    );
}

fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let (head, stdin_mode) = if args.last().is_some_and(|v| v == "--passphrase-stdin") {
        (&args[..args.len() - 1], true)
    } else {
        (&args[..], false)
    };
    match head {
        [_, action, invitation, directory, request] if action == "request" => {
            let password = read_password(true, stdin_mode)?;
            initialize_from_invitation(
                Path::new(invitation),
                Path::new(directory),
                Path::new(request),
                password.as_bytes(),
            )?;
            println!("Encrypted device identity created; CSR request is ready");
        }
        [_, action, directory, certificate] if action == "import" => {
            let password = read_password(false, stdin_mode)?;
            import_certificate(Path::new(directory), Path::new(certificate), password.as_bytes())?;
            println!("Certificate validated against pinned CA and local key; import complete");
        }
        _ => {
            usage();
            return Err("invalid arguments".into());
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fedup-device: {error}");
        std::process::exit(1);
    }
}
