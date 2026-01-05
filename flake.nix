{
  description = "Radar";

  inputs = { nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable"; };

  outputs = { self, nixpkgs }:
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in {

      packages.x86_64-linux.default =
        pkgs.pkgsStatic.rustPlatform.buildRustPackage {
          pname = "radar";
          version = "0.2.1";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs.pkgsStatic; [ openssl ];
        };

      devShells.x86_64-linux.default = pkgs.mkShell {
        strictDeps = true;
        nativeBuildInputs = with pkgs; [
          pkg-config
          rustup
          pkgsStatic.stdenv.cc
        ];

        buildInputs = with pkgs.pkgsStatic; [ openssl ];

        CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";

        shellHook = ''
          rustup default stable
          rustup target add x86_64-unknown-linux-musl
          rustup component add rustfmt rust-analyzer rust-src clippy
        '';

      };

    };
}
