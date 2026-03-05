{
  description = "magic-cap is a command line utility for an always encrypted archive file type.";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    rust-overlay = { url = "github:oxalica/rust-overlay"; };
  };
  outputs = { nixpkgs, rust-overlay, ... }:
    let
      system = "x86_64-linux";
    in {
      packages.${system}.default =
        let
          pkgs = import nixpkgs { inherit system; };
            in pkgs.rustPlatform.buildRustPackage {
              pname = "magic_cap";
              buildInputs = [ ];
              version = "0.1.0";
              cargoLock.lockFile = ./Cargo.lock;
              src = pkgs.lib.cleanSource ./.;
            };
            devShells.${system}.default =
              let pkgs = import nixpkgs {
                    inherit system;
                    overlays = [ (import rust-overlay) ];
                    config.allowUnfree = true;
                  };
              in
                pkgs.mkShell {
                  packages = with pkgs; [
                    llvmPackages.llvm
                    (rust-bin.stable.latest.default.override {
                      extensions = [ "rust-analyzer" "rust-src" "llvm-tools-preview" ];
                    })
                    cargo
                    cargo-autoinherit
                    cargo-depgraph
                    cargo-duplicates
                    cargo-edit
                    cargo-llvm-cov
                    cargo-wizard
                    clippy
                    gnuplot
                  ];
                };
    };
}
