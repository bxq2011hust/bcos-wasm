use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_parse_expand(&[package_name.as_str()])
        .with_include("evmc/evmc.h")
        .with_pragma_once(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("include/FBWASM.h");
}
