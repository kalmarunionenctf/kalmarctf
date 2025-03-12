{
  lib,
  inputs,
  pkgs,
  modulesPath,
  ...
}: let
  # Include nixpkgs referenced in the challenge already in the store so the initial build is faster
  nixpkgs-for-chall = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/8532db2a88ba56de9188af72134d93e39fd825f3.tar.gz";
    sha256 = "sha256-tttEXgKimgbtPvxFl+Avos4P4lssIqxHhxpLbbvNekk=";
  };
  dummy-drv = pkgs.writeShellScriptBin "__dummy-nixpkgs-ref" ''echo "${nixpkgs-for-chall}"'';
in{
  imports = [
    "${modulesPath}/profiles/minimal.nix"
  ];

  environment.systemPackages = [dummy-drv];

  microvm = {
    interfaces = lib.mkDefault [
      {
        type = "tap";
        id = "tap0";
        mac = "AA:FC:00:00:00:01";
      }
    ];
    storeOnDisk = true;
    writableStoreOverlay = "/nix/.rw-store";
    qemu.extraArgs = [
      "-netdev"
      "type=user,id=my-shrd-net,hostfwd=tcp::8080-:80"
      "-device"
      "virtio-net-device,netdev=my-shrd-net"
    ];
    mem = 3 * 1024;
  };

  nixpkgs.hostPlatform = "x86_64-linux";

  security = {
    sudo.enable = false;
    polkit.enable = false;
  };

  users.users.root.initialHashedPassword = "!";
  users.users.chall = {
    isNormalUser = true;
    initialHashedPassword = "!";
    group = "chall";
  };
  users.groups.chall = { };
  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;

  services.openssh.enable = false;

  systemd.network.enable = true;
  systemd.network.wait-online.enable = false;
  boot.initrd.systemd.enable = true;
  system.switch.enable = false;
  networking = {
    nameservers = [
      "1.1.1.1"
      "1.0.0.1"
    ];
    hostName = "nixos";
    useNetworkd = true;
    firewall.allowedTCPPorts = [ 80 ];
  };

  nix.settings = {
    allow-import-from-derivation = false;
    experimental-features = [
      "flakes"
      "nix-command"
      "no-url-literals"
    ];
  };

  boot.postBootCommands = ''
    rm -rf /jail-chall || true
    cp -R "${./chall}" /jail-chall
    chown -R chall:chall /jail-chall
    chmod -R +rw /jail-chall
  '';

  systemd.services."nixjail-challenge" = {
    wantedBy = [ "multi-user.target" ];
    environment.PORT = "80";
    environment.CHALL_DIR = "/jail-chall";
    serviceConfig = {
      ExecStart = lib.getExe inputs.self.packages.${pkgs.system}.ui;
      User = "chall";
      Group = "chall";
      RestrictAddressFamilies = [
        "AF_UNIX"
        "AF_INET"
        "AF_INET6"
      ];
      AmbientCapabilities = [
        "CAP_NET_BIND_SERVICE"
        "CAP_SYS_RESOURCE"
      ];
      CapabilityBoundingSet = [
        "CAP_NET_BIND_SERVICE"
        "CAP_SYS_RESOURCE"
      ];
      PrivateTmp = true;
    };
  };

  system.stateVersion = "22.04";
}
