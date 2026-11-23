{
  description = "Development toolchain for the icmp-socket crate";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = with pkgs; (pkgs.mkShell {
          packages = [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
          ];
        });

        # Kani needs its own pinned nightly, so it is installed with rustup
        # (in ~/.kani) on first use. `scripts/kani` runs the proofs.
        devShells.kani = pkgs.mkShell {
          # CBMC calls `gcc` to preprocess C; macOS has only clang.
          packages = [ pkgs.rustup (pkgs.writeShellScriptBin "gcc" ''exec cc "$@"'') ];
          shellHook = ''
            export RUSTUP_HOME=$HOME/.kani/rustup CARGO_HOME=$HOME/.kani/cargo
            export PATH=$CARGO_HOME/bin:$PATH
            if ! command -v cargo-kani >/dev/null; then
              rustup toolchain install stable --profile minimal
              cargo +stable install --locked kani-verifier --version 0.68.0
              cargo kani setup
            fi
          '';
        };
      });
}
