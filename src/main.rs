fn main() {
    if let Err(err) = hush::cli::run() {
        eprintln!("hush: {err}");
        std::process::exit(err.exit_code());
    }
}
