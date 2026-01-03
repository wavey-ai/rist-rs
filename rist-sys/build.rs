use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let library = pkg_config::Config::new()
        .atleast_version("0.2")
        .probe("librist")
        .expect("librist not found. Install librist and ensure pkg-config can find it.");

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("rist_.*")
        .allowlist_type("rist_.*")
        .allowlist_var("RIST_.*")
        .generate_comments(true)
        .derive_debug(true)
        .derive_default(true);

    for path in &library.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
