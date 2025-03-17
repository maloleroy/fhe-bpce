FROM rust:latest

RUN rustup component add clippy rustfmt && \
    apt update -y && \
    apt upgrade -y && \
    apt install -y clang cmake
