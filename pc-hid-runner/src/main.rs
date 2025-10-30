use std::process;

fn main() {
    pretty_env_logger::init();

    if let Err(err) = pc_hid_runner::cli::run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}
