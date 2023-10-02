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
          pkgs = import nixpkgs
            {
              inherit system;
              overlays = [
                (
                  final: prev: {
                    # using patched bpftool
                    bpftool =
                      prev.stdenv.mkDerivation {
                        pname = "bpftool";
                        version = "eunomia-edition-20230311";
                        src = prev.fetchFromGitHub {
                          owner = "eunomia-bpf";
                          repo = "bpftool";
                          rev = "05940344f5db18d0cb1bc1c42e628f132bc93123";
                          sha256 = "sha256-g2gjixfuGwVnFlqCMGLWVPbtKOSpQI+vZwIZciXFPTc=";
                          fetchSubmodules = true;
                        };

                        buildInputs = with prev; [ llvmPackages_15.clang elfutils zlib llvmPackages_15.libllvm.dev ];

                        buildPhase = ''
                          make -C src
                        '';

                        installPhase = ''
                          mkdir -p $out/include/bpf
                          cp libbpf/src/* $out/include/bpf
                          mkdir -p $out/bin
                          cp src/bpftool $out/bin
                        '';
                      };
                  }
                )
              ];
            };
          vmlinux =
            with pkgs;(stdenv.mkDerivation
              {
                pname = "vmlinux";
                version = "eunomia-edition-20230514";

                src =
                  pkgs.fetchFromGitHub {
                    owner = "eunomia-bpf";
                    repo = "vmlinux";
                    rev = "933f83becb45f5586ed5fd089e60d382aeefb409";
                    sha256 = "sha256-CVEmKkzdFNLKCbcbeSIoM5QjYVLQglpz6gy7+ZFPgCY=";
                  };

                installPhase = ''
                  runHook preInstall
                  cp -r $src $out
                  runHook postInstall
                '';

              });

          ecli = pkgs.stdenv.mkDerivation rec {
            name = "ecli";
            inherit version;
            src = self;
            cargoRoot = "ecli";
            cargoDeps = pkgs.rustPlatform.importCargoLock {
              lockFile = ./${cargoRoot}/Cargo.lock;
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
              cd ${cargoRoot}
            '';

            OPENSSL_NO_VENDOR = 1;

            installPhase = ''
              mkdir -p $out/bin
              install -Dm 755 target/release/ecli-rs $out/bin/
              install -Dm 755 target/release/ecli-server $out/bin/
            '';
            inherit meta;
          };
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
            ecc = pkgs.stdenv.mkDerivation rec{
              pname = "ecc";

              inherit version;
              src = self;

              cargoRoot = "compiler/cmd";

              cargoDeps = pkgs.rustPlatform.importCargoLock {
                lockFile = ./${cargoRoot}/Cargo.lock;
              };

              nativeBuildInputs = with pkgs;[
                cmake
                pkg-config
              ]
              ++
              (with rustPlatform;
              [
                cargoSetupHook
                bindgenHook
                cargo
                rustc
              ]);

              buildInputs = with pkgs;[
                llvmPackages_latest.clang
                elfutils
                zlib
              ];

              dontUseCmakeConfigure = true;

              preBuild = ''
                rm compiler/cmd/build.rs # requires network access
                export OUT_DIR=$(pwd)
                mkdir -p $OUT_DIR/workspace/{include,bin}
                cp -r ${vmlinux} $OUT_DIR/workspace/include/vmlinux
                cp ${pkgs.bpftool}/bin/bpftool $OUT_DIR/workspace/bin
                cp -r ${pkgs.bpftool}/include $OUT_DIR/workspace
                cd ${cargoRoot}
                cargo build --release
              '';

              postInstall = ''
                mkdir -p $out/bin
                install -Dm 755 target/release/ecc-rs $out/bin/
              '';

            };
            bpftool = pkgs.bpftool;
          };

          devShells = rec {

            default = eunomia-dev;

            eunomia-dev = pkgs.mkShell {
              inputsFrom = with packages;
                [ ecc ecli ] ++ (with pkgs;[ llvmPackages.bintools ]);

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
