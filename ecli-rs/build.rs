fn main() {
    println!("cargo:rustc-link-search=../bpf-loader/build/lib/Release");
    println!("cargo:rustc-link-search=../wasm-runtime/build/lib/Release");
    println!("cargo:rustc-link-search=../wasm-runtime/build");
    println!("cargo:rustc-link-search=/lib/x86_64-linux-gnu");

    println!("cargo:rustc-link-lib=static=eunomia");
    println!("cargo:rustc-link-lib=static=ewasm");
    println!("cargo:rustc-link-lib=static=vmlib");
    println!("cargo:rustc-link-lib=static=stdc++");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");
}
