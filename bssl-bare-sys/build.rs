// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::path::PathBuf;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());

    // Build openssl.
    let bssl_src = "third-party/boringssl";
    println!("cargo::rerun-if-changed={}", bssl_src);
    let bssl_dst = cmake::build(bssl_src);
    for lib_dir in ["lib", "lib64"] {
        println!(
            "cargo::rustc-link-search={}",
            bssl_dst.join(lib_dir).into_os_string().into_string().unwrap()
        );
    }

    // Generate the binding.
    // Essentially translated verbatim from boringssl/rust/bssl-sys/CMakeLists.txt.
    let bssl_src_path = PathBuf::from(bssl_src);
    let bssl_src_rust_bssl_sys_path = bssl_src_path.join("rust").join("bssl-sys");
    let bssl_src_rust_bssl_sys_bindgen_hdr = bssl_src_rust_bssl_sys_path
        .join("wrapper.h")
        .into_os_string()
        .into_string()
        .unwrap();
    let bssl_dst_include_path = bssl_dst.join("include");
    let bssl_dst_include_dir = bssl_dst_include_path.clone().into_os_string().into_string().unwrap();
    let bindgen_wrapper_rs_out_path = out_path.join("wrapper.rs");
    let bindgen_wrapper_c_out_path = out_path.join("wrapper.c");
    let bindings = bindgen::Builder::default()
        .header(&bssl_src_rust_bssl_sys_bindgen_hdr)
        .allowlist_file(bssl_src_rust_bssl_sys_bindgen_hdr)
        .allowlist_file(format!(
            "{}.*\\.h",
            bssl_dst_include_path
                .join("openssl")
                .into_os_string()
                .into_string()
                .unwrap()
        ))
        .enable_function_attribute_detection()
        .use_core()
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .rustified_enum("point_conversion_form_t")
        .wrap_static_fns(true)
        .wrap_static_fns_path(bindgen_wrapper_c_out_path.clone())
        .clang_arg(format!("-I{}", bssl_dst_include_dir))
        .generate()
        .expect("Failed to generate bssl bindings");
    bindings
        .write_to_file(bindgen_wrapper_rs_out_path.clone())
        .expect("Failed to write bssl bindings");
    println!(
        "cargo::rustc-env=BSSL_BARE_SYS_BINDGEN_WRAPPER_RS={}",
        bindgen_wrapper_rs_out_path.into_os_string().into_string().unwrap()
    );

    // Compile the generated static-function wrappers.
    cc::Build::new()
        .file(bindgen_wrapper_c_out_path.into_os_string().into_string().unwrap())
        .include(".")
        .include(bssl_dst_include_dir)
        .compile("bssl-bare-sys-wrapper");
    println!("cargo::rustc-link-search={}", out_dir);

    // Add the generated objects to the link.
    println!("cargo::rustc-link-lib=bssl-bare-sys-wrapper");
    println!("cargo::rustc-link-lib=ssl");
    println!("cargo::rustc-link-lib=crypto");
}
