# Nix flake for config-sync
# Build: nix build github:gregnazario/config-sync
# Run:   nix run github:gregnazario/config-sync -- init
# Install (NixOS): add to environment.systemPackages
{
  description = "Sync config files across machines with post-quantum E2E encryption";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "config-sync";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            cmake
            pkg-config
          ];

          buildInputs = with pkgs; [
            dbus
            clang
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.CoreFoundation
          ];

          buildAndTestSubcommand = "build --release --manifest-path crates/cs-cli/Cargo.toml";

          # Tests need a Secret Service session; skip in Nix sandbox.
          doCheck = false;

          postInstall = ''
            # The build puts the binary in $out/bin already via the [[bin]] name.
          '';

          meta = with pkgs.lib; {
            description = "Sync config files across machines with post-quantum E2E encryption";
            homepage = "https://github.com/gregnazario/config-sync";
            license = with licenses; [ mit asl20 ];
            platforms = platforms.unix ++ platforms.windows;
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/config-sync";
        };
      });
}
