{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          nativeBuildInputs = with pkgs; [ rustToolchain pkg-config openssl nettle glibc llvmPackages.libcxxClang llvmPackages.libclang clang ];
        in
        with pkgs;
        {
          devShells.default = mkShell {
						NIX_LIBGCC_S_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
						NIX_GLIBC_PATH = "${pkgs.glibc.out}/lib";
						LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";
            BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${llvmPackages.libclang.lib}/lib/clang/${lib.getVersion clang}/include";
            inherit nativeBuildInputs;
          };
        }
      );
}
