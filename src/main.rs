fn main() {
    if let Err(e) = kryptor::get_args().and_then(kryptor::run) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

