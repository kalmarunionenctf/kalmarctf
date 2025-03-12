{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixpkgs-unstable";
    microvm.url = "github:astro/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      microvm,
      rust-overlay,
      ...
    }:
    let
      s = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${s}.extend rust-overlay.overlays.default;
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          "rust-src"
          "rust-analyzer"
        ];
      };
    in
    {
      nixosConfigurations =
        let
          base = nixpkgs.lib.nixosSystem {
            modules = [
              microvm.nixosModules.microvm
              ./base.nix
            ];

            specialArgs = { inherit inputs; };
          };
        in
        {
          qemu = base.extendModules {
            modules = [
              {
                microvm.hypervisor = "qemu";
                microvm.interfaces = [ ];

                services.getty.autologinUser = "root";
              }
            ];
          };

          firecracker = base.extendModules {
            modules = [
              {
                microvm.kernelParams = [ "vmnet=%VM_NET%" ];
                microvm.hypervisor = "firecracker";
                microvm.storeDiskErofsFlags = [ ];
                services.getty.autologinUser = "root";
                systemd.services."chall-setup" = {
                  wantedBy = [ "network-pre.target" ];
                  serviceConfig.ExecStart = pkgs.writeShellScript "chall-setup.sh" ''
                    ALL_KERNEL_ARGS=$(cat /proc/cmdline | tr ' ' '\n')
                    IP_ARG=$(echo -n "$ALL_KERNEL_ARGS" | grep vmnet | cut -d'=' -f2)

                    mkdir -p /etc/systemd/network

                    cat <<EOF > /etc/systemd/network/10-static.network
                    [Match]
                    Name=eth0

                    [Network]
                    Address=''${IP_ARG}.2/24
                    Gateway=''${IP_ARG}.1
                    EOF
                  '';
                };
              }
            ];
          };
        };

      packages.${s} =
        let
          mkMicrovmPkg = cfg: self.nixosConfigurations.${cfg}.config.microvm.declaredRunner;
          rustPlatform = pkgs.makeRustPlatform {
            rustc = rust;
            cargo = rust;
          };
        in
        {
          qemu = mkMicrovmPkg "qemu";
          firecracker-unwrapped = mkMicrovmPkg "firecracker";
          firecracker = pkgs.symlinkJoin {
            name = self.packages.${s}.firecracker-unwrapped.name;
            paths = [ self.packages.${s}.firecracker-unwrapped ];
            postBuild = ''
              cd "$out/bin"
              cp --remove-destination "$(readlink -f microvm-run)" microvm-run
              chmod +w microvm-run
              CONFIG_FILE="$(grep -o -- '--config-file [^[:space:]]\+' microvm-run | cut -d' ' -f2)"
              sed -i "s,$CONFIG_FILE,<(sed \"s|%VM_NET%|\$1|g\" $CONFIG_FILE),g" microvm-run
            '';
            meta.mainProgram = "microvm-run";
          };
          ui = pkgs.callPackage ./ui/package.nix { inherit rustPlatform; };
        };

      devShells.${s}.default = pkgs.mkShell {
        packages = [
          rust
          pkgs.qemu_kvm
          pkgs.firecracker
        ];
      };

      formatter.${s} = pkgs.nixfmt-rfc-style;
    };
}
