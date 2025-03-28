FROM rust:latest

RUN rustup component add clippy rustfmt && \
    apt update -y && \
    apt upgrade -y && \
    apt install -y g++ cmake git

ARG OPENFHE_INSTALL=/openfhe-install

WORKDIR /
RUN git clone https://github.com/openfheorg/openfhe-development.git
WORKDIR /openfhe-development

RUN mkdir ${OPENFHE_INSTALL}
RUN cmake -B ${OPENFHE_BUILD:-build} -DBUILD_SHARED=ON -DCMAKE_INSTALL_PREFIX=${OPENFHE_INSTALL} .

RUN make -C ${OPENFHE_BUILD:-build} -j$(nproc)
RUN make -C ${OPENFHE_BUILD:-build} install

WORKDIR /

COPY . .