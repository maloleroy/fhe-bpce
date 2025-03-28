use cmake::Config;
use std::env;
use std::path::{Path, PathBuf};

fn compile_native(profile: &str, out_path: &Path) {
    let gmp = pkg_config::probe_library("gmp").expect("GMP not found");
    let ntl = pkg_config::probe_library("ntl").expect("NTL not found");

    let mut builder = Config::new("openfhe-development");

    builder
        .define("CMAKE_BUILD_TYPE", profile)
        .define("CMAKE_CXX_FLAGS_RELEASE", "-DNDEBUG -O3")
        .define("CMAKE_C_FLAGS_RELEASE", "-DNDEBUG -O3")
        .define("WITH_OPENMP", "OFF")
        .define("BUILD_SHARED", "ON")
        // Pass include and library paths for dependencies
        .define("GMP_INCLUDES", gmp.include_paths[0].to_str().unwrap())
        .define(
            "GMP_LIBRARIES",
            gmp.link_paths[0].join("libgmp.so").to_str().unwrap(),
        )
        .define("NTL_INCLUDES", ntl.include_paths[0].to_str().unwrap())
        .define(
            "NTL_LIBRARIES",
            ntl.link_paths[0].join("libntl.so").to_str().unwrap(),
        );

    // setup_macos_cross_compile(&mut builder); // SEAL, commented out for now

    let dst = builder.build();

    let out_path_suffix = if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        profile
    } else {
        ""
    };

    // Tell cargo to look for shared libraries in the specified directory
    println!(
        "cargo:rustc-link-search=native={}/build/lib/{}",
        dst.display(),
        out_path_suffix
    );

    // Tell cargo to tell rustc to link the static library seal.
    // println!("cargo:rustc-link-lib=static=sealc-4.0");
    // println!("cargo:rustc-link-lib=static=seal-4.0");

    // println!("-I{}", out_path.join("include").display());
}

fn main() {
    // debug/release
    let profile = std::env::var("PROFILE").expect("Failed to get build profile");
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target = std::env::var("TARGET").expect("Failed to get target");

    println!("cargo:rerun-if-changed=openfhe-development");

    let profile = if profile == "release" {
        "Release"
    } else if profile == "debug" {
        "Debug"
    } else {
        panic!("Unknown profile type {}", profile);
    };

    compile_native(profile, &out_path);

    // Tell cargo to tell rustc to link the shared libraries.
    add_link_libs();

    let bindings = bindgen::builder()
        .clang_arg("-Iopenfhe-development/src")
        .clang_arg("-Iopenfhe-development/src/binfhe/include")
        .clang_arg("-Iopenfhe-development/src/core/include")
        .clang_arg("-Iopenfhe-development/src/pke/include")
        .header("bindgen_wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings!");
}

fn add_link_libs() {
    println!("cargo:rustc-link-lib=OPENFHEpke");
    println!("cargo:rustc-link-lib=OPENFHEbinfhe");
    println!("cargo:rustc-link-lib=OPENFHEcore");

    // linking OpenMP
    // println!("cargo::rustc-link-arg=-fopenmp");
}
