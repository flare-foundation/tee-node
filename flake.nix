{
  description = "TEE node binary with or without extension (ie. signing) server enabled.";

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
            vendorHash = "sha256-n7FbFSW54e1zarc7arrAR6QUvsZAqwgiYdQkz7OgVbE=";
            doCheck = false;
          };
          with-extension = pkgs.buildGoModule {
            pname = "tee-node with extension support";
            version = "0.1.0";
            src = ./.;
            subPackages = [ "cmd/extension" ];
            inherit goModules;
            vendorHash = "sha256-n7FbFSW54e1zarc7arrAR6QUvsZAqwgiYdQkz7OgVbE=";
            doCheck = false;
          };
          docker = pkgs.dockerTools.buildLayeredImage {
            name = "tee-node";
            tag = "latest";
            contents = [
              self.packages.${system}.default
              pkgs.cacert
            ];
            config = {
              Env = [
                "TZ=UTC"
                "MODE=0"
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
              Labels = {
                "tee.launch_policy.allow_env_override" = "LOG_LEVEL,PROXY_URL,INITIAL_OWNER,EXTENSION_ID";
              };
              ExposedPorts = {
                "5500/tcp" = { };
              };
              Cmd = [ "${self.packages.${system}.default}/bin/cmd" ];
            };
          };
        };
      }
    );
}
