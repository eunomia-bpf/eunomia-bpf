{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, flake-utils, nixpkgs }:
    flake-utils.lib.eachSystem
      (with flake-utils.lib.system;
      [ x86_64-linux aarch64-linux riscv64-linux ])
      (system:
        let
          pkgs = import nixpkgs { inherit system; };
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
                    llvmPackages_14.clang
                    pkg-config
                    cmake
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

                  dontUseCmakeConfigure = true;

                  preBuild = ''
                    make -C ./bpf-loader INSTALL_LOCATION=$out/lib -e install
                    make -C ./wasm-runtime build-cpp
                    cd ${cargoRoot}
                  '';

                  installPhase = ''
                    mkdir -p $out/bin
                    install -Dm 755 target/release/ecli $out/bin/
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
                  make -C compiler
                  cd ${cargoRoot}
                '';

                installPhase = ''
                  mkdir -p $out/bin
                  install -Dm 755 target/release/ecc $out/bin/
                '';

              };
            };
          devShells.default = pkgs.mkShell {
            inputsFrom = with packages; [ ecc ecli ];
          };
        });
}
