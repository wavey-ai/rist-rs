use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let library = pkg_config::Config::new()
        .atleast_version("0.2.20")
        .probe("librist")
        .expect("librist 0.2.20 or later is required and must be available through pkg-config.");

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("rist_.*")
        .allowlist_type("rist_.*")
        .allowlist_var("RIST_.*")
        // Doxygen's `@param[out]` syntax is emitted as a broken intra-doc
        // link, so keep the raw bindings free of upstream C comments.
        .generate_comments(false)
        // bindgen's generated offset assertions use `offset_of!`, which was
        // stabilized after this workspace's MSRV.
        .layout_tests(false)
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
