# Building instructions

> The main resource tutorial for this crate is available [here](https://rust-lang.github.io/rust-bindgen). For additional resources on how to use `bindgen` see
> - [OpenFHE's build.rs file](https://github.com/fairmath/openfhe-rs/blob/master/build.rs)
> - [SEAL's build.rs file](https://github.com/marcosfpr/sealy/blob/dev/sealy/build.rs)

The goal is to be able to include the building step of OpenFHE's libraries and header files in the crate's building process, making the us of this crate easy for any Rust user, like `sealy` does. 

## Rust dependencies

- Add `bindgen` and `cmake` as build-dependencies
```bash
cargo add --build bindgen
cargo add --build cmake
```

## OpenFHE C++ code

1. Download the OpenFHE code
```bash
git submodule add https://github.com/openfheorg/openfhe-development.git
```
2. Create a wrapper header file
```bash
find openfhe-development -type f -name "*.h" | xargs printf "#include <%s>\n" > bindgen_wrapper.h
```
