{
  description = "magic-cap is a command line utility for an always encrypted archive file type.";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    rust-overlay = { url = "github:oxalica/rust-overlay"; };
  };
  outputs = { self, nixpkgs, rust-overlay, ... }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system}.default =
      let
        pkgs = import nixpkgs { inherit system; };
      in pkgs.rustPlatform.buildRustPackage {
        pname = "magic-cap";
        buildInputs = [ ];
        version = "0.1.0";
        cargoLock.lockFile = ./Cargo.lock;
        src = pkgs.lib.cleanSource ./.;
        meta.mainProgram = "mcap";
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
            valgrind
          ];
        };
    apps.${system} = {

      paramtest = {
        type = "app";
        program = pkgs.lib.getExe (pkgs.writeShellScriptBin "paramtest" ''
          echo ''${1:-defaultvalue}
        '');
      };

      cov = {
        type = "app";
        meta.description = "run tests and report coverage by opening a new firefox tab.";
        program = pkgs.lib.getExe (pkgs.writeShellScriptBin "cov" ''
          cargo llvm-cov --html
          ${pkgs.firefox} --new-tab --url ./target/llvm-cov/html/index.html
        '');
      };
      memuse = {
        type = "app";
        meta.description = "run valgrind wrapping magic-cap, report the max heap usage.";
        program = pkgs.lib.getExe (pkgs.writeShellScriptBin "memuse" ''
          INPUT=''${1:-kitten.mcap}
          if [ -f $INPUT ]; then
          ${pkgs.lib.getExe' pkgs.valgrind "valgrind"} --tool=massif --time-unit=B --massif-out-file=data/heap.usage.massif -- ${pkgs.lib.getExe self.packages.${system}.default} encrypt $INPUT --ciphertext data/kitten.mcap.mcap
          HEAP=''$(${pkgs.lib.getExe pkgs.ripgrep} mem_heap_B data/heap.usage.massif|cut -d '=' -f 2|sort -r -g|head -n 1)
          SIZE=''$(du -b $INPUT)
          echo "Max heap usage of $HEAP bytes for encoding $SIZE bytes"
          # Clearly I am bad at doing math in the shell.
          # echo "Max heap used is ''$(printf '2.f\n' "$(($HEAP*100/$SIZE))e-2") percent of the input file."
          fi
        '');
      };
    };
  };
}
