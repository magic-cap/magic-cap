{
  description = "magic-cap is a command line utility for an always encrypted archive file type.";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = { url = "github:oxalica/rust-overlay"; };
  };
  outputs = { nixpkgs, nixpkgs-unstable, rust-overlay, ... }:
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
                  upkgs = import nixpkgs-unstable { inherit system; };
              in
                pkgs.mkShell {
                  packages = with pkgs; [ rust-bin.stable.latest.default upkgs.rust-analyzer cargo pkg-config clippy ];
                };
    };
}
