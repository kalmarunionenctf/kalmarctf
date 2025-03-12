let
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/8532db2a88ba56de9188af72134d93e39fd825f3.tar.gz";
    sha256 = "sha256-tttEXgKimgbtPvxFl+Avos4P4lssIqxHhxpLbbvNekk=";
  };
  pkgs = import nixpkgs { };
  inherit (pkgs) lib;
  no-builtins = import ./no-builtins.nix;
  user-input = builtins.scopedImport no-builtins ./user-input.nix;
  # TODO: Make sure the user does not reference the flag
  user-drv = assert lib.isDerivation user-input; pkgs.hello // user-input;
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "nixjail";
  version = "0.0.1";

  dontUnpack = true;

  # FIXME: The user should not be able to execute arbitrary code
  # Ref: https://github.com/NixOS/nixpkgs/blob/master/pkgs/stdenv/generic/make-derivation.nix
  nativeBuildInputs = [user-drv];
  buildPhase = ''
    runHook preBuild
    # TODO: Enable building
    # "${user-drv}/bin/build"
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p "$out"
    echo kalmarctf{not-this-flag} > "$out/flag"
  '';
}
