extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // FIXME: fix hardcoded abs path
    // because cargo publish is not working with relative path, we need to use absolute path
    println!("cargo:rustc-link-search=../eunomia-bpf/build/lib/Release");
    println!("cargo:rustc-link-search=../eunomia-bpf/build/libbpf");
    println!("cargo:rustc-link-search=/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=/lib32");

    println!("cargo:rustc-flags=-l dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=stdc++");

    // Tell cargo to tell rustc to link
    println!("cargo:rustc-link-lib=static=eunomia");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
