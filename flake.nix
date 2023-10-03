{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
    wasm-bpf.url = "github:eunomia-bpf/wasm-bpf";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, flake-utils, nixpkgs, pre-commit-hooks, wasm-bpf }:
    flake-utils.lib.eachSystem
      (with flake-utils.lib.system; [ x86_64-linux aarch64-linux ])
      (system:
        let
          version = pkgs.lib.substring 0 8 self.lastModifiedDate or self.lastModified or "19700101";
          meta = with pkgs.lib; {
            homepage = "https://eunomia.dev";
            license = licenses.mit;
            maintainers = with maintainers; [ undefined-moe ];
          };
          pkgs = import nixpkgs { inherit system; };

          bpftool = (with pkgs; stdenv.mkDerivation {
            pname = "bpftool";
            version = "eunomia-edition-20230311";
            src = fetchFromGitHub {
              owner = "eunomia-bpf";
              repo = "bpftool";
              rev = "05940344f5db18d0cb1bc1c42e628f132bc93123";
              hash = "sha256-g2gjixfuGwVnFlqCMGLWVPbtKOSpQI+vZwIZciXFPTc=";
              fetchSubmodules = true;
            };

            buildInputs = [ llvmPackages_15.clang elfutils zlib llvmPackages_15.libllvm.dev ];

            buildPhase = ''
              make -C src
            '';

            installPhase = ''
              # compatible with `build.rs` from upstream
              mkdir -p $out/src/libbpf
              cp -r src/libbpf/include $out/src/libbpf
              cp src/bpftool $out/src
            '';
          });

          vmlinux = pkgs.fetchFromGitHub {
            owner = "eunomia-bpf";
            repo = "vmlinux";
            rev = "933f83becb45f5586ed5fd089e60d382aeefb409";
            hash = "sha256-CVEmKkzdFNLKCbcbeSIoM5QjYVLQglpz6gy7+ZFPgCY=";
          };

          ecli = pkgs.stdenv.mkDerivation (finalAttrs: {
            name = "ecli";
            inherit version;
            src = self;
            cargoRoot = "ecli";
            cargoDeps = pkgs.rustPlatform.importCargoLock {
              lockFile = ./${finalAttrs.cargoRoot}/Cargo.lock;
            };

            nativeBuildInputs = with pkgs;[
              pkg-config
            ]
            ++
            (with rustPlatform;
            [
              cargoSetupHook
              cargo
              rustc
            ]);

            buildInputs = with pkgs;[
              zlib.static
              elfutils
              zlib
              openssl.dev
              llvmPackages.bintools
            ];

            preBuild = ''
              cd ${finalAttrs.cargoRoot}
            '';

            OPENSSL_NO_VENDOR = 1;

            installPhase = ''
              mkdir -p $out/bin
              install -Dm 755 target/release/ecli-rs $out/bin/
              install -Dm 755 target/release/ecli-server $out/bin/
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
            ecli-server = pkgs.stdenv.mkDerivation {
              name = "ecli-server";
              inherit version;
              src = ecli;
              installPhase = ''
                install -Dm 755 $src/bin/ecli-server $out/bin/ecli-server
              '';
              inherit meta;
            };
            ecc = (with pkgs; llvmPackages_16.stdenv.mkDerivation (finalAttrs: {
              pname = "ecc";
              inherit version;

              src = self;

              cargoRoot = "compiler/cmd";

              cargoDeps = rustPlatform.importCargoLock {
                lockFile = ./${finalAttrs.cargoRoot}/Cargo.lock;
              };

              nativeBuildInputs = [
                pkg-config
              ]
              ++
              (with rustPlatform;
              [
                cargoSetupHook
                bindgenHook
                cargo
                rustc
                makeWrapper
              ]);

              buildInputs = [
                elfutils
                zlib
              ];

              preBuild = ''
                export SANDBOX=1
                export OUT_DIR=$(pwd)
                export VMLINUX_DIR=${vmlinux}
                export BPFTOOL_DIR=${bpftool}
                cd ${finalAttrs.cargoRoot}
                cargo build --release
              '';

              postInstall = ''
                mkdir -p $out/bin
                install -Dm 755 target/release/ecc-rs $out/bin/
              '';

              postFixup = ''
                wrapProgram $out/bin/ecc-rs --prefix LIBCLANG_PATH : ${llvmPackages_16.libclang.lib}/lib \
                  --prefix PATH : ${lib.makeBinPath (with llvmPackages_16; [clang bintools-unwrapped])}
              '';
              inherit meta;
            }));

            inherit bpftool;
          };

          devShells = rec {

            default = eunomia-dev;

            eunomia-dev = pkgs.mkShell {
              inputsFrom = with packages;[ ecc ecli ];
            };

            ebpf-dev = eunomia-dev // pkgs.mkShell {
              buildInputs = (with pkgs; [ libbpf ])
              ++ [ packages.ecli packages.ecc packages.ecli-server ]
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
            ecli-server = {
              type = "app";
              program = "${self.packages.${system}.ecli}/bin/ecli-server";
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
