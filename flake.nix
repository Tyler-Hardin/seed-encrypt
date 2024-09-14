{
  description = "Rust project with libseccomp";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system}.default = pkgs.rustPlatform.buildRustPackage {
      name = "seed-encrypt";
      src = ./.;

      cargoLock = { lockFile = ./Cargo.lock; };

      nativeBuildInputs = with pkgs; [
        clang
        rustc
        cargo
        clippy
      ];

      buildInputs = with pkgs; [
        libclang.lib
        libseccomp
      ];

      LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
      RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
    };
  };
}

