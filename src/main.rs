use bootstrapped::is_wasm;

fn main() {
    if is_wasm() {
        println!("Running in WASM environment");
    } else {
        println!("ready");
    }
}
