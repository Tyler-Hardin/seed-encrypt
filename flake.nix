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


      buildInputs = with pkgs; [
        libseccomp
      ];
    };
  };
}

