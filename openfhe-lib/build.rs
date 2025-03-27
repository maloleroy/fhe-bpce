use std::env;
use std::path::PathBuf;

fn main() {
    // see https://github.com/fairmath/openfhe-rs/tree/master/crate_usage
    let home = env::var("HOME").expect("HOME not set");
    let lib_path = PathBuf::from(home).join("mylibs");
    println!("cargo::rerun-if-changed=src/main.rs");

    cxx_build::bridge("src/main.rs")
        .include(lib_path.join("include"))
        // Add any additional C++ source files if needed.
        // Set the required C++ standard if needed.
        .flag_if_supported("-std=c++14")
        .compile("openfhe");

    // Link to your OpenFHE libraries.
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=OPENFHEpke");
    println!("cargo:rustc-link-lib=OPENFHEbinfhe");
    println!("cargo:rustc-link-lib=OPENFHEcore");

    // For OpenMP linking.
    println!("cargo:rustc-link-arg=-fopenmp");
    // Set the rpath.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path.display());

    // Re-run build if your source file changes.
    println!("cargo:rerun-if-changed=src/main.rs");
}
