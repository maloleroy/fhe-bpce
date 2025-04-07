```
          .                            .                      .
  .                  .             -)------+====+       .
                           -)----====    ,'   ,'   .                 .
              .                  `.  `.,;___,'                .
                                   `, |____l_\
                    _,.....------c==]""______ |,,,,,,.....____ _
    .      .       "-:______________  |____l_|]'''''''''''       .     .
                                  ,'"",'.   `.
         .                 -)-----====   `.   `.
                     .            -)-------+====+       .            .
             .                               .
```

# Homomorphic Encryption Library

This repository is a Rust crate that provides a simple interface to homomorphic encryption schemes.
It is designed to be easy to use and to provide a high-level interface to the underlying encryption schemes.

## Schemes

The library currently supports the following schemes:
- BFV (Seal)
- BGV (Seal)
- CKKS (Seal)
- TFHE (Zama)

## Usage

Main crate can be built using `cargo build --release`, or run in debug mode for tests using `cargo run`.
You can get more information about it using `--help`.

You can read the documentation of each crate of the workspace using `cargo doc --open`.

### Examples

You will find useful examples in `examples/`. You can run them with `cargo run --example <name>`.

### Benchmarks

You can start benchmarks found in `benches/` by running `cargo bench`.

There are other benchmarks in the workspace's crates. You can use `cargo bench --workspace` to start them all.

## Architecture

The main binary uses crates to organize its dependencies. For more information about their usage,
use `cargo doc --open -p <crate>`.

### fhe-core

It is the core crate of the workspace that defines the core `CryptoSystem` trait.
All of the crates deeply integrates `bincode` to serialize data and send it over the network.

### fhe-operations

Implements complex operations on ciphered data:
- SQL-like : SELECT ... WHERE ...
- Sign function
- Sequential operations

### seal-lib

Implements `CryptoSystem` for systems backed by Microsoft SEAL (BFV, BGV and CKKS).

It relies on an external crate, `sealy`. This crate provides convenient wrappers around Rust bindings of Microsoft SEAL.
As this crate is no longer maintained and ships an outdated version of Microsoft SEAL,
an updated version of the crate is provided in `seal-lib/sealy`. It is licensed under MIT.

### zama-lib

Implements `CryptoSystem` for systems backed by Zama (TFHE).

It relies on an external crate, `tfhe`. This crate provides a Rust implementation of the TFHE cryptosystem.
Note that currently, the underlying crate fails to build its documentation.
Please use `cargo doc --open --no-deps -p zama-lib`
