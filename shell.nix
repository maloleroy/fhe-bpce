{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.llvmPackages.libclang
    pkgs.clang
    pkgs.gccStdenv
    pkgs.cmake
    pkgs.pkg-config
  ];

  shellHook = ''
    export LIBCLANG_PATH="/nix/store/ymbp8lmggn7qgb8lwrzyzxnbyz77x08r-clang-19.1.6-lib/lib"
    export LD_LIBRARY_PATH=$LIBCLANG_PATH:$LD_LIBRARY_PATH
    export NIX_GCC=${pkgs.gccStdenv.cc}
    export CPLUS_INCLUDE_PATH=$NIX_GCC/include/c++:$NIX_GCC/include
    export LIBRARY_PATH=$NIX_GCC/lib
    export CPATH=$NIX_GCC/include
  '';
}
