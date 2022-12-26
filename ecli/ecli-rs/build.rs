extern crate bindgen;

fn main() {
    println!("cargo:rustc-link-search=../../bpf-loader/build/lib/Release");
    println!("cargo:rustc-link-search=../../wasm-runtime/build/lib/Release");
    println!("cargo:rustc-link-search=../../wasm-runtime/build");
    println!("cargo:rustc-link-search=/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=../../bpf-loader/build/libbpf");

    println!("cargo:rustc-link-lib=static=eunomia");
    println!("cargo:rustc-link-lib=static=ewasm");
    println!("cargo:rustc-link-lib=static=vmlib");
    println!("cargo:rustc-link-lib=static=stdc++");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let wasm_bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("../../wasm-runtime/include/ewasm/ewasm.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate ewasm bindings");

    wasm_bindings
        .write_to_file("src/ewasm_runner/ewasm_bpf.rs")
        .expect("Couldn't write ewasm bindings!");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let json_bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("../../bpf-loader/include/eunomia/eunomia-bpf.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate json bindings");

    json_bindings
        .write_to_file("src/json_runner/eunomia_bpf.rs")
        .expect("Couldn't write ewasm bindings!");
}
