# shell.nix or default.nix
with import <nixpkgs> {};
pkgs.mkShell {
  nativeBuildInputs = [
    m4
    gcc
    cmake
  ];
}
