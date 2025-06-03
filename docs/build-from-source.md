# Build Conflux from Source Code

## Install Build Dependencies

Conflux requires **Rust 1.77.2**, ```clang```, and ```sqlite``` to build.

We recommend installing Rust through [rustup](https://rustup.rs/). If you don't already have ```rustup``` or ```clang```, you can install them like this:

### Linux

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# you might need to run 
# source "$HOME/.cargo/env"
# to configure your shell
rustup install 1.77.2
```

Other dependencies including ```clang```, ```cmake (version >= 3.12 and < 4.0)``` and ```sqlite (version >= 3.8.3 and < 4.0)``` can be installed with:

- Ubuntu 18.04-22.04:

```bash
# The latest cmake version on Ubuntu 18.04 is 3.10, so you'll need to install it from the Kitware repository.
# This step is not required on Ubuntu 22.04
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null

sudo apt-get update
sudo apt-get install clang libsqlite3-dev pkg-config libssl-dev cmake
```

- CentOS 7 / RHEL:

```bash
sudo yum install epel-release
sudo yum install clang gcc gcc-c++ openssl-devel cmake3 wget

# This may fail if you have installed cmake with version 2.8.
# You can choose to uninstall cmake first.
sudo ln -s /usr/bin/cmake3 /usr/bin/cmake

# The official sqlite version on CentOS 7 is 3.7.17, so we need to install the latest version from the source code.
# The source code have be downloaded from https://www.sqlite.org/download.html
wget https://www.sqlite.org/2020/sqlite-autoconf-3320100.tar.gz
tar xfvz sqlite-autoconf-3320100.tar.gz
cd sqlite-autoconf-3320100
./configure
make
sudo make install
```

### OSX

```shell
curl https://sh.rustup.rs -sSf | sh
# you might need to run 
# source "$HOME/.cargo/env"
# to configure your shell
rustup install 1.77.2
```

You might need to install ```brew``` if you need to use it to install ```clang```:

```shell
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

```clang``` comes with Xcode command line tools, and can also be installed with homebrew:

```shell
brew install llvm
```

You also need to install other dependencies with homebrew and set up the environment variables as described after the installation:

```shell
brew install openssl pkg-config cmake bzip2 
```

### Windows

Make sure you have Visual Studio 2015 with C++ support installed. Next, download and run the ```rustup``` installer from [this link](https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe), start ```VS2015 x64 Native Tools Command Prompt```, and use the following command to install and set up the ```msvc``` toolchain:

```shell
rustup default stable-x86_64-pc-windows-msvc
```

```clang``` can be installed with LLVM. Pre-built binaries can be downloaded from [Download LLVM](https://releases.llvm.org/download.html#8.0.0). Make sure to add LLVM to the system PATH as instructed.

Make sure that these binaries are in your ```PATH``` (the instruction will be shown after installing ```rustup```). After that, you should be able to build Conflux from source.

## Build from Source Code

After installing the dependencies mentioned above, now you can clone our repository and start building the executable binary. The latest mainnet node version is **{confluxNodeVersion.mainnet}**.

```bash
# download Conflux code
git clone https://github.com/Conflux-Chain/conflux-rust
cd conflux-rust
git checkout <latest-released-mainnet-version> # checkout to the latest release version

# Usually, you just need the latest source code without the complete history. You can speed up the cloning process with the following command.
git clone -b <latest-released-mainnet-version> --single-branch --depth 1 https://github.com/Conflux-Chain/conflux-rust.git
cd conflux-rust

# build in release mode
cargo build --release
```

If you are building on MacOS and get the error: `could not find native static library bz2` you can try the following command:

```bash
RUSTFLAGS="-L $(brew --prefix bzip2)/lib -l bz2" cargo build
```


This produces an executable called **conflux** in the **./target/release** subdirectory. The **conflux** binary it a client software that we can use to run a node.

Note, when compiling a crate and you receive errors, it's in most cases your outdated version of Rust, or some of your crates have to be recompiled. Cleaning the repository will most likely solve the issue if you are on the latest stable version of Rust, try:

```shell
cargo clean && cargo update
```
When you compiling on Linux system，By default cc is linked to gcc, you need to export the cc environment variable to point to clang

```shell
CC=clang CXX=clang++ cargo build --release
```

To start running a Conflux full node, you can follow the instructions at [Running Conflux Full Node](https://doc.confluxnetwork.org/docs/general/run-a-node/).

## FAQs

### Why the build process failed?

Please make sure you install all the dependencies, and your network is good to download rust crates. If you are in China, you can try to use [rustup](https://rustup.rs/) to install rust and set the mirror to [Rust China](https://mirrors.tuna.tsinghua.edu.cn/help/rustup/).

### Is mainnet and testnet client compatible?

No, the mainnet and testnet client are not same.

### How to build the testnet client?

Checkout to the latest testnet tag and build the source code. The latest version of testnet is **{confluxNodeVersion.testnet}**.

```bash
git checkout <latest-released-testnet-version>  # checkout to the latest testnet release version
cargo build --release
```

### Where to find the latest release version?

You can find the latest release version at [Releases](https://github.com/Conflux-Chain/conflux-rust/releases)
