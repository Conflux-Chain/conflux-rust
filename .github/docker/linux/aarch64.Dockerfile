ARG UBUNTU_VERSION=18.04
FROM ubuntu:${UBUNTU_VERSION}

ARG UBUNTU_CODENAME=bionic

ARG OPENSSL_VERSION=3.5.1
ARG OPENSSL_SHA256=529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f

ARG AARCH64_MARCH=armv8-a
ARG AARCH64_MTUNE=generic

ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture arm64 && \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.sources

RUN tee /etc/apt/sources.list.d/amd64.list > /dev/null <<EOF
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ ${UBUNTU_CODENAME} main restricted universe multiverse
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ ${UBUNTU_CODENAME}-backports main restricted universe multiverse
deb [arch=amd64] http://security.ubuntu.com/ubuntu/ ${UBUNTU_CODENAME}-security main restricted universe multiverse
EOF

RUN tee /etc/apt/sources.list.d/arm64.list > /dev/null <<EOF
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${UBUNTU_CODENAME} main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${UBUNTU_CODENAME}-backports main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${UBUNTU_CODENAME}-security main restricted universe multiverse
EOF

RUN apt-get update && \
    apt-get install -y \
      ca-certificates \
      cmake \
      curl \
      git \
      gnupg \
      perl \
      pkg-config \
      software-properties-common \
      wget && \
    wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 18 && \
    apt-get install -y \
      crossbuild-essential-arm64 \
      libsqlite3-dev:arm64 \
      libc++-18-dev:arm64 && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f llvm.sh

ENV CROSS_COMPILE=aarch64-linux-gnu-

RUN set -ex; \
    wget -O /tmp/openssl.tar.gz "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"; \
    echo "${OPENSSL_SHA256} /tmp/openssl.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/openssl.tar.gz -C /tmp; \
    cd "/tmp/openssl-${OPENSSL_VERSION}"; \
    perl ./Configure linux-aarch64 --prefix=/opt/openssl-aarch64 --openssldir=/opt/openssl-aarch64 no-tests -march="${AARCH64_MARCH}" -mtune="${AARCH64_MTUNE}"; \
    make -j"$(nproc)"; \
    make install_sw; \
    cd /; \
    rm -rf "/tmp/openssl-${OPENSSL_VERSION}" /tmp/openssl.tar.gz

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal --default-toolchain none -y
ENV PATH="/root/.cargo/bin:${PATH}"

ENV OPENSSL_STATIC=yes
ENV CC_aarch64_unknown_linux_gnu="clang-18"
ENV CXX_aarch64_unknown_linux_gnu="clang++-18"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="clang-18"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="\
  -C linker=clang-18 \
  -C link-arg=--target=aarch64-linux-gnu \
  -C link-arg=-fuse-ld=lld \
  -C link-arg=-L/usr/lib/aarch64-linux-gnu \
  -C link-arg=-lc++ \
  -C link-arg=-lc++abi"
ENV PKG_CONFIG_ALLOW_CROSS=1

ENV CFLAGS_aarch64_unknown_linux_gnu="--target=aarch64-linux-gnu -march=${AARCH64_MARCH}"
ENV CXXFLAGS_aarch64_unknown_linux_gnu="--target=aarch64-linux-gnu -march=${AARCH64_MARCH} -stdlib=libc++"

ENV OPENSSL_DIR_aarch64_unknown_linux_gnu=/opt/openssl-aarch64
ENV OPENSSL_LIB_DIR_aarch64_unknown_linux_gnu=/opt/openssl-aarch64/lib
ENV OPENSSL_INCLUDE_DIR_aarch64_unknown_linux_gnu=/opt/openssl-aarch64/include
ENV PKG_CONFIG_PATH_aarch64_unknown_linux_gnu=/opt/openssl-aarch64/lib/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig

WORKDIR /workspace
RUN git config --global --add safe.directory /workspace
