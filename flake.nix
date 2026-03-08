{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
    wasm-bpf.url = "github:eunomia-bpf/wasm-bpf";
    naersk.url = "github:nix-community/naersk";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, flake-utils, nixpkgs, pre-commit-hooks, wasm-bpf, naersk }:
    flake-utils.lib.eachSystem
      (with flake-utils.lib.system; [ x86_64-linux aarch64-linux ])
      (system:
        let
          pkgs = import nixpkgs { inherit system; };
          naersk' = pkgs.callPackage naersk { };
          version = pkgs.lib.substring 0 8 self.lastModifiedDate or self.lastModified or "19700101";
          meta = with pkgs.lib; {
            homepage = "https://eunomia.dev";
            license = licenses.mit;
            maintainers = with maintainers; [ undefined-moe ];
          };
          ecliRustTriple = if system == "x86_64-linux" then "x86_64-unknown-linux-gnu" else "aarch64-unknown-linux-gnu";
          ecliRustHash = if system == "x86_64-linux" then "sha256-v/iXTy0+5sDmrJJrUz9lu902l9LCuSW9rl9Fue7RCmc=" else "sha256-WfGIP83S1yQ9L9HtGfIuBSGSUSJ6us+j1lauv7zF6Dg=";
          ecliRustToolchain = pkgs.stdenvNoCC.mkDerivation {
            pname = "rust-toolchain";
            version = "1.90.0";
            src = pkgs.fetchurl {
              url = "https://static.rust-lang.org/dist/rust-1.90.0-${ecliRustTriple}.tar.xz";
              hash = ecliRustHash;
            };
            nativeBuildInputs = [ pkgs.patchelf ];
            dontConfigure = true;
            dontBuild = true;
            installPhase = ''
              runHook preInstall
              patchShebangs .
              ./install.sh --prefix=$out --disable-ldconfig

              dynamicLinker="$(cat ${pkgs.stdenv.cc}/nix-support/dynamic-linker)"
              toolchainRpath="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.zlib}/lib:$out/lib"
              find $out -type f | while read -r path; do
                if patchelf --print-interpreter "$path" >/dev/null 2>&1; then
                  patchelf --set-interpreter "$dynamicLinker" --set-rpath "$toolchainRpath" "$path"
                elif patchelf --print-rpath "$path" >/dev/null 2>&1; then
                  patchelf --set-rpath "$toolchainRpath" "$path"
                fi
              done
              runHook postInstall
            '';
          };
          ecliRustPlatform = pkgs.makeRustPlatform {
            cargo = ecliRustToolchain;
            rustc = ecliRustToolchain;
          };

          bpftool = pkgs.llvmPackages.stdenv.mkDerivation {
            pname = "bpftool";
            version = "unstable-2023-03-11";

            # this fork specialized for some functions
            # and has eventually been embedded into the ecc binary
            src = pkgs.fetchFromGitHub {
              owner = "eunomia-bpf";
              repo = "bpftool";
              rev = "05940344f5db18d0cb1bc1c42e628f132bc93123";
              hash = "sha256-g2gjixfuGwVnFlqCMGLWVPbtKOSpQI+vZwIZciXFPTc=";
              fetchSubmodules = true;
            };

            buildInputs = with pkgs;[
              llvmPackages.libllvm
              elfutils
              zlib
            ];

            buildPhase = ''
              runHook preBuild
              make -C src
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              # We don't use the default `make install` because we are looking to create a
              # directory structure compatible with `build.rs` of `ecc`.
              mkdir -p $out/src/libbpf
              # some headers are required
              cp -r src/libbpf/include $out/src/libbpf
              cp src/bpftool $out/src
              runHook postInstall
            '';
          };

          vmlinux-headers = pkgs.fetchFromGitHub {
            owner = "eunomia-bpf";
            repo = "vmlinux";
            rev = "933f83becb45f5586ed5fd089e60d382aeefb409";
            hash = "sha256-CVEmKkzdFNLKCbcbeSIoM5QjYVLQglpz6gy7+ZFPgCY=";
          };

          standaloneRuntime = pkgs.stdenv.mkDerivation (finalAttrs: {
            pname = "ecc-standalone-runtime";
            inherit version;
            src = self;
            cargoRoot = "bpf-loader-rs";
            cargoDeps = pkgs.rustPlatform.importCargoLock {
              lockFile = ./${finalAttrs.cargoRoot}/Cargo.lock;
            };

            nativeBuildInputs = with pkgs;[
              pkg-config
              cargoSetupHook
              cargo
              rustc
            ];

            buildInputs = with pkgs;[
              elfutils
              zlib
              zlib.static
              zstd
              xz
            ];

            preBuild = ''
              cd ${finalAttrs.cargoRoot}
            '';

            buildPhase = ''
              runHook preBuild
              mkdir -p target/eunomia-standalone-runtime/release
              ( cargo rustc -p bpf-loader-c-wrapper --target-dir target/eunomia-standalone-runtime --release -- --print=native-static-libs 2>&1 \
                | awk -F 'native-static-libs: ' '/native-static-libs:/ { print $2 }'; \
                pkg-config --static --libs libelf zlib 2>/dev/null || true ) \
                | awk '{ for (i = 1; i <= NF; i++) { if ($i != "-lgcc_s") { printf "%s ", $i } } } END { print "" }' \
                > target/eunomia-standalone-runtime/release/libeunomia.a.linkflags
              test -s target/eunomia-standalone-runtime/release/libeunomia.a.linkflags
              test -f target/eunomia-standalone-runtime/release/libeunomia.a
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              install -Dm 644 target/eunomia-standalone-runtime/release/libeunomia.a $out/lib/libeunomia.a
              install -Dm 644 target/eunomia-standalone-runtime/release/libeunomia.a.linkflags $out/lib/libeunomia.a.linkflags
              runHook postInstall
            '';

            inherit meta;
          });

          ecli = pkgs.stdenv.mkDerivation (finalAttrs: {
            name = "ecli";
            inherit version;
            src = self;
            cargoRoot = "ecli";
            cargoDeps = ecliRustPlatform.importCargoLock {
              lockFile = ./${finalAttrs.cargoRoot}/Cargo.lock;
            };

            nativeBuildInputs = with pkgs;[
              pkg-config
            ]
            ++
            (with ecliRustPlatform;
            [
              cargoSetupHook
              cargo
              rustc
            ]);

            buildInputs = with pkgs;[
              zlib.static
              elfutils
              zlib
              zstd
              xz
              openssl.dev
              llvmPackages.bintools
            ];

            preBuild = ''
              cd ${finalAttrs.cargoRoot}
            '';

            buildPhase = ''
              runHook preBuild
              RUSTC=${ecliRustToolchain}/bin/rustc ${ecliRustToolchain}/bin/cargo build --release
              runHook postBuild
            '';

            OPENSSL_NO_VENDOR = 1;

            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              install -Dm 755 target/release/ecli-rs $out/bin/
              runHook postInstall
            '';
            inherit meta;
          });
        in
        rec {
          packages = {
            ecli = ecli;
            ecli-rs = pkgs.stdenv.mkDerivation {
              name = "ecli-rs";
              inherit version;
              src = ecli;
              installPhase = ''
                install -Dm 755 $src/bin/ecli-rs $out/bin/ecli-rs
              '';
              inherit meta;
            };
            ecc = (with pkgs; naersk'.buildPackage {
              pname = "ecc";
              inherit version;

              # slightly different with which in nixpkgs, for using local source
              src = ./compiler/cmd;

              nativeBuildInputs = [
                pkg-config
                makeWrapper
                rustPlatform.bindgenHook
              ];

              buildInputs = [
                elfutils
                zlib
              ];

              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER = "gcc";

              preBuild = ''
                # `SANDBOX` defined by upstream to disable build-time network access
                export SANDBOX=1
                # specify dependencies' location
                export VMLINUX_DIR=${vmlinux-headers}
                export BPFTOOL_DIR=${bpftool}
              '';

              preCheck = ''
                export HOME=$NIX_BUILD_TOP
              '';

              checkFlags = [
                # requires network access
                "--skip=bpf_compiler::tests::test_generate_custom_btf"

                # FIXME: requires dynamic link `libclang` or clang binary which are not found in check env
                "--skip=bpf_compiler::tests::test_compile_bpf"
                "--skip=bpf_compiler::tests::test_export_multi_and_pack"
                "--skip=document_parser::test::test_parse_empty"
                "--skip=document_parser::test::test_parse_maps"
                "--skip=document_parser::test::test_parse_progss"
                "--skip=document_parser::test::test_parse_variables"
              ];

              passthru = {
                inherit bpftool;
              };

              postInstall = ''
                mkdir -p $out/lib
                cp ${standaloneRuntime}/lib/libeunomia.a $out/lib/
                cp ${standaloneRuntime}/lib/libeunomia.a.linkflags $out/lib/
                wrapProgram $out/bin/ecc-rs \
                  --prefix LIBCLANG_PATH : ${llvmPackages.libclang.lib}/lib \
                  --prefix PATH : ${lib.makeBinPath (with llvmPackages; [clang bintools-unwrapped])} \
                  --prefix LIBRARY_PATH : ${lib.makeLibraryPath [ elfutils zlib.static zstd xz ]}
              '';

              inherit meta;
            });

            inherit bpftool;
          };

          devShells = rec {

            default = eunomia-dev;

            eunomia-dev = pkgs.mkShell {
              inputsFrom = with packages;[ ecc ecli ];
            };

            ebpf-dev = eunomia-dev // pkgs.mkShell {
              buildInputs = (with pkgs; [ libbpf ])
              ++ [ packages.ecli packages.ecc ]
              ++ [ wasm-bpf.packages.${system}.default ];

            };
          };

          apps = {
            ecc = {
              type = "app";
              program = "${self.packages.${system}.ecc}/bin/ecc-rs";
            };
            ecli-rs = {
              type = "app";
              program = "${self.packages.${system}.ecli}/bin/ecli-rs";
            };

          };

          checks = with pkgs; {
            pre-commit-check =
              pre-commit-hooks.lib.${system}.run
                {
                  src = lib.cleanSource ./.;
                  hooks = lib.genAttrs
                    [ "shellcheck" "black" "mdsh" ]
                    (n: { enable = true; });
                };
          };
        }) // {
      overlays.default =
        final: prev:
        (prev.lib.genAttrs
          (prev.lib.attrNames (self.packages))
          (n: self.packages.${n}));

    };
}
