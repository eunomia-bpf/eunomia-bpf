extern crate clang;
use clang::*;

fn test_clang() {
    // Acquire an instance of `Clang`
    let clang = Clang::new().unwrap();

    // Create a new `Index`
    let index = Index::new(&clang, false, false);

    // Parse a source file into a translation unit
    let tu = index
        .parser("/home/yunwei/eunomia-bpf/eunomia-cc/cmd/test/client.bpf.c")
        .arguments(&[
            "-g",
            "-O2",
            "-target bpf",
            "-D__TARGET_ARCH_x86",
            "-idirafter /usr/lib/llvm-15/lib/clang/15.0.2/include",
            "-idirafter /usr/local/include",
            "-idirafter /usr/include/x86_64-linux-gnu",
            "-idirafter /usr/include",
            "-I/home/yunwei/.eunomia/include",
            "-I/home/yunwei/.eunomia/include/vmlinux/x86",
        ])
        .parse()
        .unwrap();

    // Get the structs in this translation unit
    let structs = tu
        .get_entity()
        .get_children()
        .into_iter()
        .filter(|e| {
            e.get_location()
                    .unwrap()
                    .get_file_location()
                    .file
                    .unwrap()
                    .get_path()
                    .to_str().unwrap()
                    == "/home/yunwei/eunomia-bpf/eunomia-cc/cmd/test/client.bpf.c"
        })
        .collect::<Vec<_>>();

    // Print information about the structs
    for e in structs {
        println!("struct: {:?}", e);
        println!("comment: {:?}", e.get_comment());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_struct() {
        test_clang();
    }
}
