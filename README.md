# Homomorphic Encryption Library

This repository is a pure Rust crate that provides a simple interface to homomorphic encryption schemes.
It is designed to be easy to use and to provide a high-level interface to the underlying encryption schemes.

## Schemes

The library currently supports the following schemes:
- CKKS

## Usage

You can read the documentation using `cargo doc --open`.

## Bare metal

The crates supports `no_std` environments, but not `no_alloc` environments.

On exotic targets, you will need to provide the crate with a source of randomness.
In such a case, it is up to you to make sure the source is cryptographically secure.
For more information, check the documentation of `getrandom`.

## Architecture

The crate's API is is `src/`, while other crates of the workspace (such as `fhe-core`) serve as the backend for the encryption schemes.
