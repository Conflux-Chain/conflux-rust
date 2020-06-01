fn main() {
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=dylib=ShLwApi");
        println!("cargo:rustc-link-lib=dylib=Rpcrt4");
    }
}
