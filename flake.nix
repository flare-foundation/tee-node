{
  description = "TEE node binary with extension (ie. signing) server enabled. Useful for building images with TEE node + extension.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      gomod2nix,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        gomod2nixLib = gomod2nix.lib pkgs;
        goModules = gomod2nixLib.generateGoModules {
          name = "go-modules";
          TOML = ./gomod2nix.toml;
        };
      in
      {
        packages = {
          default = pkgs.buildGoModule {
            pname = "tee-node";
            version = "0.1.0";
            src = ./.;
            subPackages = [ "cmd/" ];
            inherit goModules;
            vendorHash = "sha256-GUqlv/ZKDb7UifZgTQc/RxxpyCUUFoEZLetAtffekqQ=";
            doCheck = false;
          };
          with-extension = pkgs.buildGoModule {
            pname = "tee-node with extension support";
            version = "0.1.0";
            src = ./.;
            subPackages = [ "cmd/extension" ];
            inherit goModules;
            vendorHash = "sha256-GUqlv/ZKDb7UifZgTQc/RxxpyCUUFoEZLetAtffekqQ=";
            doCheck = false;
          };
        };
      }
    );
}
