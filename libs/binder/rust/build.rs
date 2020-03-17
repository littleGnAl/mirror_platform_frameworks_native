extern crate bindgen;

use std::path::Path;

fn main() {
    println!("cargo:rustc-link-lib=binder");
    println!("cargo:rerun-if-changed=binder.h");

    let bindings = bindgen::Builder::default()
        .clang_arg("-I../include")
        .clang_arg("-I../../../../../system/core/libutils/include")
        .clang_arg("-I../../../../../system/core/liblog/include")
        .clang_arg("-I../../../../../system/core/libsystem/include")
        .clang_arg("-I../../../../../system/core/base/include")
        .clang_arg("-I../../../../../system/core/libcutils/include")
        .clang_args(&["-x", "c++"])
        .clang_arg("-std=gnu++17")
        .header("binder.h")
        .whitelist_type("android::BBinder")
        .whitelist_type("android::BpBinder")
        .whitelist_type("android::Parcel")
        .whitelist_type("android::sp")
        .whitelist_type("android::IServiceManager")
        .whitelist_type("android::IBinder")
        .whitelist_type("android::RefBase")
        .whitelist_type("android::Vector")
        .whitelist_type("android::binder::Status")
        .whitelist_type("android::ProcessState")
        .whitelist_type("android::IPCThreadState")
        .opaque_type("android::thread_id_t")
        .opaque_type("std::.*")
        // Bindgen doesn't lay out BpBinder and BBinder correctly due to indirect
        // virtual inheritance. We don't want to make all of android::* opaque,
        // though, because we need to see the contents of some classes, e.g., sp.
        .opaque_type("android::BpBinder")
        .opaque_type("android::BBinder")
        // custom implementations
        .blacklist_type("android::IServiceManager")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .derive_debug(false)
        .generate()
        .expect("Bindgen failed to generate bindings for libbinder");

    // write bindings
    let out_path = Path::new("src/native/libbinder_bindings.rs");
    bindings.write_to_file(&out_path).unwrap_or_else(|_| {
        panic!(
            "Bindgen failed to writing bindings to {}",
            out_path.display()
        )
    });
}
