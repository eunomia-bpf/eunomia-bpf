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
        vmlinux = pkgs.fetchFromGitHub {
          owner = "eunomia-bpf";
          repo = "vmlinux";
          rev = "933f83becb45f5586ed5fd089e60d382aeefb409";
          hash = "sha256-CVEmKkzdFNLKCbcbeSIoM5QjYVLQglpz6gy7+ZFPgCY=";
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
        packages.ecc = pkgs.stdenv.mkDerivation rec {
          name = "ecc";
          inherit version;
          src = self;
          cargoRoot = "compiler/cmd";
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./${cargoRoot}/Cargo.lock;
          };
          nativeBuildInputs = with pkgs; [
            pkg-config
            elfutils
            zlib
            python3
            cargo
            rustc
            rustPlatform.cargoSetupHook
            rustPlatform.bindgenHook
          ];
          buildInputs = with pkgs; [  ];
          preBuild = ''
            mkdir -p compiler/workspace/include
            mkdir -p compiler/workspace/bin
            ln -s ${vmlinux} compiler/workspace/include/vmlinux
            cp ${pkgs.bpftool}/bin/bpftool compiler/workspace/bin
          '';
          dontMake = true;
          buildPhase = ''
            cd compiler/cmd
            export OUT_DIR=.
            cargo build --release
          '';
          installPhase = ''
            mkdir -p $out/bin
            chmod +x target/release/ecc-rs
            cp target/release/ecc-rs $out/bin/ecc
          '';
        };
      }
    );
}
