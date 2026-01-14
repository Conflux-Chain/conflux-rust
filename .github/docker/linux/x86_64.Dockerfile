ARG UBUNTU_VERSION=18.04
FROM ubuntu:${UBUNTU_VERSION}

ARG OPENSSL_VERSION=3.5.1
ARG OPENSSL_SHA256=529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f

ARG CPU_MARCH=haswell
ARG RUST_TARGET_CPU=haswell

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
      ca-certificates \
      cmake \
      curl \
      git \
      gnupg \
      libsqlite3-dev \
      make \
      perl \
      pkg-config \
      software-properties-common \
      unzip \
      wget && \
    wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 18 && \
    apt-get install -y libc++-18-dev && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f llvm.sh

RUN set -ex; \
    wget -O /tmp/openssl.tar.gz "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"; \
    echo "${OPENSSL_SHA256} /tmp/openssl.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/openssl.tar.gz -C /tmp; \
    cd "/tmp/openssl-${OPENSSL_VERSION}"; \
    CC=clang-18 CXX=clang++-18 ./config --prefix=/opt/openssl --openssldir=/opt/openssl no-tests "-march=${CPU_MARCH}"; \
    make -j"$(nproc)"; \
    make install_sw; \
    cd /; \
    rm -rf "/tmp/openssl-${OPENSSL_VERSION}" /tmp/openssl.tar.gz

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal --default-toolchain none -y

ENV PATH="/root/.cargo/bin:${PATH}"
ENV CC=clang-18
ENV CXX=clang++-18

ENV CFLAGS="-march=${CPU_MARCH}"
ENV CXXFLAGS="-march=${CPU_MARCH} -std=c++11 -stdlib=libc++"
ENV LDFLAGS="-stdlib=libc++"

ENV RUSTFLAGS="-C target-cpu=${RUST_TARGET_CPU}"

ENV OPENSSL_STATIC=yes
ENV OPENSSL_DIR=/opt/openssl
ENV OPENSSL_LIB_DIR=/opt/openssl/lib64
ENV OPENSSL_INCLUDE_DIR=/opt/openssl/include
ENV PKG_CONFIG_PATH=/opt/openssl/lib64/pkgconfig

WORKDIR /workspace
RUN git config --global --add safe.directory /workspace
