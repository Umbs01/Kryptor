fn main() {
    if let Err(e) = cryptor::get_args().and_then(cryptor::run) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

