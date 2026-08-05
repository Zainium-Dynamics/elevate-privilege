//! nologin — deny login to a user (port of shadow-4.17.2 `src/nologin.c`).

fn main() {
    eprintln!("This account is currently not available.");
    std::process::exit(1);
}
