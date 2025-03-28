# Building instructions

> The main resource tutorial for this crate is available [here](https://rust-lang.github.io/rust-bindgen). For additional resources on how to use `bindgen` see
> - [OpenFHE's build.rs file](https://github.com/fairmath/openfhe-rs/blob/master/build.rs)
> - [SEAL's build.rs file](https://github.com/marcosfpr/sealy/blob/dev/sealy/build.rs)

The goal is to be able to include the building step of OpenFHE's libraries and header files in the crate's building process, making the us of this crate easy for any Rust user, like `sealy` does.

1. Download the OpenFHE code
```bash
git submodule add https://github.com/openfheorg/openfhe-development.git
```
2. Install the [GNU m4](https://www.gnu.org/software/m4/m4.html) macro processor
```
sudo apt install m4
```
This will eventually be built locally instead of relying on a system-wide package. For reference, the source code can be downloaded with
```bash
git clone git://git.sv.gnu.org/m4
```

# To do
- Fix the numerous errors & warnings we currently get while compiling the Rust lib
- Write a clean Rust interface, with correctly implemented drop features