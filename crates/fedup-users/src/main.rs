fn main() {
    if let Err(error) = fedup_users::run_cli() {
        eprintln!("fedup-users: {error}");
        std::process::exit(1);
    }
}
