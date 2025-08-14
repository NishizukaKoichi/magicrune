fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "wasm32" {
        println!("cargo:rustc-cfg=target_wasm");
    }
}
