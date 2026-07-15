{
  description = "Rust cross-compilation environment for NixOS";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      overrides.toolchain.channel = "stable";
      pkgs = nixpkgs.legacyPackages.${system};
      pkgsCross = pkgs.pkgsCross.x86_64-freebsd;
      target = "x86_64-unknown-freebsd";

      sysroot = pkgs.fetchzip {
        hash = "sha256-OLnHge+hTwjvMNTiChI7YWOhkFUJKj2WQ33SaCa7h4E=";
        stripRoot = false;
        url = "https://download.freebsd.org/releases/amd64/15.0-RELEASE/base.txz";
      };
    in
    {
      devShells.default = pkgs.mkShell rec {
        nativeBuildInputs = [
          pkgs.pkg-config
          pkgsCross.cargo
          pkgsCross.clang
        ];

        RUSTC_TOOLCHAIN = overrides.toolchain.channel;

        RUSTFLAGS = [
          "-Clinker=clang"
          "-Clink-arg=--target=${target}"
          "-Clink-arg=--sysroot=${sysroot}"
        ];

        shellHook = ''
          export PATH=$PATH:''${CARGO_HOME}:-~/.cargo}/bin
        '';
      };
    }
  );
}
