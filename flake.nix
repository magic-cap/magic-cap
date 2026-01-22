{
  description = "magic-cap is a command line utility for an always encrypted archive file type.";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    rust-overlay = { url = "github:oxalica/rust-overlay"; };
  };
  outputs = { nixpkgs, rust-overlay, ... }:
    let
      system = "x86_64-linux";
    in {
      packages.${system}.default =
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.rustPlatform.buildRustPackage {
          pname = "magic_cap";
          nativeBuildInputs = [ pkgs.pkg-config ];
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
            libraries = with pkgs; [  ];
            packages = with pkgs; [ rust-bin.stable.latest.default rust-analyzer cargo pkg-config clippy ];
            shellHook = ''
            export PKG_CONFIG_PATH=${pkgs.lib.concatStrings ["${pkgs.libudev-zero}" "/lib/pkgconfig"]}
            '';
          };
    };
}
