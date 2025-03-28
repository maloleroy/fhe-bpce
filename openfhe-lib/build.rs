use cmake::Config;
use std::env;
use std::fs::{create_dir_all, remove_dir_all};
use std::path::{Path, PathBuf};
use xz2::read::XzDecoder;

fn download_and_build_gmp(out_dir: &Path) -> (PathBuf, PathBuf) {
    let gmp_version = "6.3.0";
    let gmp_url = format!("https://gmplib.org/download/gmp/gmp-{}.tar.xz", gmp_version);
    let source_dir = out_dir.join("gmp-src");
    let build_dir = out_dir.join("gmp-build");
    let install_dir = build_dir.join("install");

    // Download and extract
    if !source_dir.exists() {
        let _ = remove_dir_all(&source_dir);
        let _ = remove_dir_all(&build_dir);
        let resp = reqwest::blocking::get(&gmp_url).unwrap().bytes().unwrap();
        let tar = XzDecoder::new(&resp[..]);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(&out_dir).unwrap();
        std::fs::rename(out_dir.join(format!("gmp-{}", gmp_version)), &source_dir).unwrap();
    }
    println!(
        "cargo:warning=GMP debug mode. Check directory: {}",
        source_dir.display()
    );

    // Create build directories
    let _ = create_dir_all(&build_dir);
    let _ = create_dir_all(&install_dir);

    // Build using autotools
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            r#"cd "{src}" && 
            ./configure --prefix="{install}" --disable-shared --enable-static --with-pic &&
            make -j$(nproc) &&
            make install"#,
            src = source_dir.display(),
            install = install_dir.display()
        ))
        .status()
        .expect("Failed to build GMP");

    if !status.success() {
        panic!("GMP build failed with exit code: {}", status);
    }

    let lib_dir = install_dir.join("lib");
    println!("cargo:rustc-link-search={}", lib_dir.display());

    println!("cargo:warning=Built dependency GMP");
    (install_dir.join("include"), lib_dir)
}

fn download_and_build_ntl(
    profile: &str,
    out_dir: &Path,
    gmp_include: &Path,
    gmp_lib: &Path,
) -> (PathBuf, PathBuf) {
    let ntl_version = "11.5.1";
    let ntl_url = format!("https://libntl.org/ntl-{}.tar.gz", ntl_version);
    let source_dir = out_dir.join("ntl-src");
    let build_dir = out_dir.join("ntl-build");
    println!(
        "cargo:warning=NTL debug mode. Check directory: {}",
        source_dir.display()
    );
    // Download and extract
    if !source_dir.exists() {
        let _ = remove_dir_all(&source_dir);
        let _ = remove_dir_all(&build_dir);
        let resp = reqwest::blocking::get(&ntl_url).unwrap().bytes().unwrap();
        let tar = flate2::read::GzDecoder::new(&resp[..]);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(&out_dir).unwrap();
        std::fs::rename(out_dir.join(format!("ntl-{}", ntl_version)), &source_dir).unwrap();
    }

    // Build with PIC
    let install_dir = build_dir.join("install");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            r#"cd "{src}/src" && 
            ./configure PREFIX="{install}" SHARED=off CXXFLAGS="-g {optimize} -I{gmp_include} -L{gmp_lib} -fPIC" &&
            make -j$(nproc) &&
            make install"#,
            src = source_dir.display(),
            install = install_dir.display(),
            optimize = if profile == "Release" { "-O2" } else { "-O2" },
            gmp_include = gmp_include.display(),
            gmp_lib = gmp_lib.display()
        ))
        .status()
        .expect("Failed to build NTL");

    if !status.success() {
        panic!("NTL build failed with exit code: {}", status);
    }

    let lib_dir = install_dir.join("lib");
    println!("cargo:rustc-link-search={}", lib_dir.display());

    println!("cargo:warning=Built dependency NTL");
    (install_dir.join("include"), lib_dir)
}

fn compile_openfhe(
    profile: &str,
    out_dir: &Path,
    gmp_lib: &Path,
    ntl_lib: &Path,
) -> PathBuf {
    let mut config = Config::new("openfhe-development");

    config
        // .define("CXX", compiler.path())
        .define("CMAKE_BUILD_TYPE", profile)
        .define("BUILD_SHARED", "ON")
        .define("WITH_OPENMP", "OFF")
        .define("NTL_THREADS", "OFF")
        .define("BUILD_UNITTESTS", "OFF")
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_BENCHMARKS", "OFF")
        .define(
            "CMAKE_PREFIX_PATH",
            format!(
                "{};{}",
                gmp_lib.parent().unwrap().parent().unwrap().display(),
                ntl_lib.parent().unwrap().parent().unwrap().display()
            ),
        )
        .define("GMP_ROOT", gmp_lib.parent().unwrap().parent().unwrap())
        .define("NTL_ROOT", ntl_lib.parent().unwrap().parent().unwrap());

    println!("cargo:warning=Building OpenFHE in {}", out_dir.display());

    let dst = config.build();
    println!(
        "cargo:warning=Finished building OpenFHE in {}",
        out_dir.display()
    );

    println!("cargo:rustc-link-search={}/build/lib", dst.display());
    dst
}

fn get_cpp_compiler() -> cc::Tool {
    let compiler = cc::Build::new().cpp(true).get_compiler();

    println!(
        "cargo:warning=Using C++ compiler: {}",
        compiler.path().display()
    );
    compiler
}

fn get_system_includes(compiler: &cc::Tool) -> Vec<PathBuf> {
    let output = std::process::Command::new(compiler.path())
        .args(&["-E", "-x", "c++", "-", "-v"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("Failed to execute compiler");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut includes = Vec::new();
    let mut in_includes = false;

    for line in stderr.lines() {
        if line.contains("#include <...> search starts here:") {
            in_includes = true;
            continue;
        }
        if line.contains("End of search list") {
            in_includes = false;
            continue;
        }
        if in_includes {
            let path = line.trim();
            if !path.is_empty() {
                includes.push(PathBuf::from(path));
            }
        }
    }

    includes
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs"); // Force rebuild on script changes
    let compiler = get_cpp_compiler();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let profile = match env::var("PROFILE").unwrap().as_str() {
        "release" => "Release",
        _ => "Debug",
    };

    // Build dependencies
    let (gmp_include, gmp_lib) = download_and_build_gmp(&out_dir);
    let (ntl_include, ntl_lib) = download_and_build_ntl(profile, &out_dir, &gmp_include, &gmp_lib);

    // Build OpenFHE
    let openfhe_dst = compile_openfhe(
        profile,
        &out_dir,
        &gmp_lib,
        &ntl_lib,
    );

    println!("cargo:warning=Built OpenFHE in {}", openfhe_dst.display());

    // Linker configuration
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=static=ntl");
    println!("cargo:rustc-link-lib=dylib=OPENFHEcore");
    println!("cargo:rustc-link-lib=dylib=OPENFHEpke");
    println!("cargo:rustc-link-lib=dylib=OPENFHEbinfhe");

    let include_base = openfhe_dst.join("include").join("openfhe");

    // Generate bindings
    let bindings = bindgen::Builder::default()
        // Add these two lines at the start of the chain
        .clang_arg("-x")
        .clang_arg("c++")
        .clang_arg("-std=c++17")
        // Include directories
        .clang_arg(format!("-I{}", include_base.display()))
        .clang_arg(format!("-I{}", include_base.join("binfhe").display()))
        .clang_arg(format!("-I{}", include_base.join("cereal").display()))
        .clang_arg(format!("-I{}", include_base.join("core").display()))
        .clang_arg(format!("-I{}", include_base.join("pke").display()))
        .clang_arg(format!("-I{}", gmp_include.display()))
        .clang_arg(format!("-I{}", ntl_include.display()))
        .clang_args(
            get_system_includes(&compiler)
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        // OpenFHE header
        .header(include_base.join("pke").join("openfhe.h").to_string_lossy().into_owned())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Failed to write bindings");
}
