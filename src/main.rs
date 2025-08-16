use bootstrapped::is_wasm;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "--version" {
        println!("bootstrapped 0.1.0");
        std::process::exit(0);
    }

    if is_wasm() {
        println!("Running in WASM environment");
    } else {
        println!("ready");
    }
}
