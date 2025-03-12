{
  lib,
  makeWrapper,
  rustPlatform, nix,
}:

rustPlatform.buildRustPackage {
  pname = "ui";
  version = "2025";
  useFetchCargoVendor = true;
  src = lib.cleanSource ./.;
  cargoHash = "sha256-j3AZyGE1qsYFRNeReLMSUBTqXUmzh++dcycrQpF1Leg=";

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    wrapProgram "$out/bin/ui" \
      --prefix PATH : "${lib.makeBinPath [ nix ]}" \
      --set-default ASSET_DIR "${./static}"
  '';

  meta.mainProgram = "ui";
}
