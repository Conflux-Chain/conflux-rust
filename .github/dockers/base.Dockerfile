FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
    curl \
    lsb-release \
    wget \
    software-properties-common \
    gnupg \
    libsqlite3-dev \
    pkg-config \
    libssl-dev \
    cmake \
    git \
    unzip && \
    wget https://apt.llvm.org/llvm.sh && \
    chmod u+x llvm.sh && \
    ./llvm.sh 18 && \
    apt-get install -y libc++-18-dev && \
    rm -rf /var/lib/apt/lists/* && \
    rm llvm.sh

WORKDIR /app

COPY rust-toolchain.toml .

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-host x86_64-unknown-linux-gnu -y && \
    . ~/.cargo/env && \
    git config --global --add safe.directory '*'

ENV PATH="/root/.cargo/bin:/home/builder/.cargo/bin:${PATH}"
ENV CC=clang-18
ENV CXX=clang++-18
ENV CXXFLAGS="-std=c++11 -stdlib=libc++"
ENV LDFLAGS="-stdlib=libc++"

