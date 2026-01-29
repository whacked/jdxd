{ pkgs ? (
    let
      inherit (builtins) fetchTree fromJSON readFile;
      inherit ((fromJSON (readFile ./flake.lock)).nodes) nixpkgs gomod2nix;
    in
    import (fetchTree nixpkgs.locked) {
      overlays = [
        (import "${fetchTree gomod2nix.locked}/overlay.nix")
      ];
    }
  )
, mkGoEnv ? pkgs.mkGoEnv
, gomod2nix ? pkgs.gomod2nix
, sdflow ? null
}:

let
  goEnv = mkGoEnv { pwd = ./.; };
  go-jsonschema = pkgs.stdenv.mkDerivation {
    name = "go-jsonschema";
    src = pkgs.fetchurl {
      url = "https://github.com/omissis/go-jsonschema/releases/download/v0.15.0/go-jsonschema_Linux_x86_64.tar.gz";
      sha256 = "diR8EUGrEcVyhW5kAyDyHluoWRnj3lUlNL2BbhUjFS4=";
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out/bin
      tar -xzf $src -C $out/bin
    '';
    buildInputs = [ pkgs.unzip ];
  };

  # Use sdflow from parameter (flake) or fetch directly (nix-shell standalone)
  sdflowPkg = if sdflow != null then sdflow
    else (builtins.getFlake "github:whacked/sdflow").packages.${pkgs.system}.default;

in
pkgs.mkShell {
  packages = [
    goEnv
    gomod2nix
    pkgs.just
    pkgs.check-jsonschema
    go-jsonschema
    sdflowPkg
  ];

  shellHook = ''
    eval "$(just --completions bash)"
    export PATH=$PWD:$PATH
  '';
}
