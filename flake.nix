{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, flake-utils, nixpkgs, pre-commit-hooks }:
    flake-utils.lib.eachSystem
      (with flake-utils.lib.system;
      [ x86_64-linux aarch64-linux ]) # riscv64-linux commented since precommithook doesn't support yet.
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;

            # this workaround could be removed after https://github.com/eunomia-bpf/eunomia-bpf/issues/183 closing.
            overlays = [
              (final: prev: {
                bpftool =
                  prev.bpftool.overrideAttrs (old: {
                    version = "eunomia-edition-20230129";
                    src = prev.fetchFromGitHub {
                      owner = "eunomia-bpf";
                      repo = "bpftool";
                      rev = "05940344f5db18d0cb1bc1c42e628f132bc93123";
                      sha256 = "sha256-g2gjixfuGwVnFlqCMGLWVPbtKOSpQI+vZwIZciXFPTc=";
                      fetchSubmodules = true;
                    };
                    patches = [ ];

                    nativeBuildInputs = with pkgs;[ bison flex llvmPackages_15.clang pkg-config ];
                    buildInputs =
                      with pkgs;[ libopcodes libbfd ]
                        ++ (with pkgs;
                      [ elfutils zlib readline libcap llvmPackages_15.llvm ]); # enable full feature

                    preConfigure = ''
                      substituteInPlace ./src/Makefile \
                        --replace '/usr/local' "$out" \
                        --replace '/usr'       "$out" \
                        --replace '/sbin'      '/bin'
                    '';

                    buildFlags = [ "bpftool" ];

                    installPhase = ''
                      make -C src install
                    '';
                  });
              })
            ];
          };
        in
        rec {
          packages =
            let
              version = pkgs.lib.substring 0 8 self.lastModifiedDate
                or self.lastModified or "19700101";
            in
            {
              ecli =
                pkgs.stdenv.mkDerivation rec{
                  pname = "ecli";
                  inherit version;
                  src = self;

                  cargoRoot = "ecli";

                  cargoDeps = pkgs.rustPlatform.importCargoLock {
                    lockFile = ./${cargoRoot}/Cargo.lock;
                  };

                  nativeBuildInputs = with pkgs;[
                    pkg-config
                    zlib.static
                    elfutils
                    zlib
                    openssl.dev
                  ]
                  ++
                  (with rustPlatform;
                  [
                    cargoSetupHook
                    bindgenHook
                    rust.cargo
                    rust.rustc
                  ]);

                  preBuild = ''
                    cd ${cargoRoot}
                  '';

                  installPhase = ''
                    mkdir -p $out/bin
                    install -Dm 755 target/release/ecli-rs $out/bin/
                    install -Dm 755 target/release/ecli-server $out/bin/
                  '';
                };

              ecc = pkgs.llvmPackages_latest.libcxxStdenv.mkDerivation rec{
                pname = "ecc";

                inherit version;
                src = self;

                cargoRoot = "compiler/cmd";

                cargoDeps = pkgs.rustPlatform.importCargoLock {
                  lockFile = ./${cargoRoot}/Cargo.lock;
                  outputHashes = {
                    "clap-4.0.32" = "sha256-KQ0URmFIVZ2XyUTJ6rmZswf9V5gkZDBBLpCLB7K+uRg=";
                  };
                };

                nativeBuildInputs = with pkgs;[ cmake pkg-config elfutils zlib python3 ]
                  ++
                  (with rustPlatform;
                  [
                    cargoSetupHook
                    bindgenHook
                    rust.cargo
                    rust.rustc
                  ]);

                buildInputs = with pkgs;[ llvmPackages_latest.clang ];

                dontUseCmakeConfigure = true;

                preBuild = ''
                    mkdir -p compiler/workspace/include/vmlinux
                    cp -r third_party/vmlinux compiler/workspace/include/vmlinux
                    cp ${pkgs.bpftool}/bin/bpftool compiler/workspace/bin
                    cd ${cargoRoot}
                    cargo build --release
                '';

                installPhase = ''
                  mkdir -p $out/bin
                  install -Dm 755 target/release/ecc $out/bin/
                '';

              };
            };
          devShells = rec {
            default = pkgs.mkShell {
              inputsFrom = with packages;
                [ ecc ecli ];
            };

            ebpf-dev = default // pkgs.mkShell {
              buildInputs = with packages; [ ecc ecli ];
            };
          };

          checks = with pkgs; {
            pre-commit-check =
              pre-commit-hooks.lib.${system}.run
                {
                  src = lib.cleanSource ./.;
                  hooks = lib.genAttrs
                    [ "shellcheck" "black" "mdsh" ]
                    (n: { enable = true; })
                  ;
                };
          };

        });
}
