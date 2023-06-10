{
  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.flake-utils.url = github:numtide/flake-utils;

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem (with flake-utils.lib.system; [ x86_64-linux aarch64-linux ]) (system:
      let
        pkgs = import nixpkgs { inherit system; };
        version = pkgs.lib.substring 0 8 self.lastModifiedDate or self.lastModified or "19700101";
        meta = with pkgs.lib; {
          description = "A tool for push, pull and run pre-compiled eBPF programs as OCI images in Wasm module";
          homepage = "https://eunomia.dev/";
          license = licenses.mit;
          maintainers = with maintainers; [ undefined-moe ];
        };
        ecli = pkgs.stdenv.mkDerivation rec {
          name = "ecli";
          inherit version;
          src = self;

          cargoRoot = "ecli";
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./${cargoRoot}/Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
            zlib.static
            elfutils
            zlib
            openssl.dev
            cargo
            rustc
            rustPlatform.cargoSetupHook
            rustPlatform.bindgenHook
          ];

          preBuild = ''
            cd ${cargoRoot}
          '';

          installPhase = ''
            mkdir -p $out/bin
            install -Dm 755 target/release/ecli-rs $out/bin/
            install -Dm 755 target/release/ecli-server $out/bin/
          '';
          inherit meta;
        };
      in
      {
        packages.ecli = ecli;
        packages.ecli-rs = pkgs.stdenv.mkDerivation {
          name = "ecli-rs";
          inherit version;
          src = ecli;
          installPhase = ''
            mkdir -p $out/bin
            cp $src/bin/ecli-rs $out/bin/ecli-rs
          '';
          inherit meta;
        };
        packages.ecli-server = pkgs.stdenv.mkDerivation {
          name = "ecli-server";
          inherit version;
          src = ecli;
          installPhase = ''
            mkdir -p $out/bin
            cp $src/bin/ecli-server $out/bin/ecli-server
          '';
          inherit meta;
        };
      }
    );
}
