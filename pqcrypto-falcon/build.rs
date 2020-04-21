extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let common_dir = Path::new("pqclean/common");
    let common_files = vec![
        common_dir.join("nistseedexpander.c"),
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("sp800-185.c"),
    ];

    cc::Build::new()
        .flag("-std=c99")
        .flag("-march=native")
        .include("pqclean/common")
        .files(common_files.into_iter())
        .compile("pqclean_common");

    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean/crypto_sign/falcon-512/clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .flag("-march=native")
            .include("pqclean/common")
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("falcon-512_clean");
    }

    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean/crypto_sign/falcon-512/avx2");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-march=native")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include("pqclean/common")
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("falcon-512_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean/crypto_sign/falcon-1024/clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .flag("-march=native")
            .include("pqclean/common")
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("falcon-1024_clean");
    }

    // keccak lib
    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        cc::Build::new()
            .flag("-std=c99")
            .flag("-march=native")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }

    // Print enableing flag for AVX2 implementation
    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
