/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate bindgen;

use std::path::Path;

fn main() {
    println!("cargo:rustc-link-lib=binder");
    println!("cargo:rerun-if-changed=src/sys/BinderBindings.h");

    let bindings = bindgen::Builder::default()
        // These include paths will be provided by soong once it supports
        // bindgen.
        .clang_arg("-I../ndk/include_ndk")
        .clang_arg("-I../ndk/include_platform")
        .clang_args(&["-x", "c++"])
        .clang_arg("-std=gnu++17")
        // Temporary
        .clang_arg("-D__INTRODUCED_IN(n)=")
        .clang_arg("-D__assert(a,b,c)=")
        // We want all the APIs to be available on the host.
        .clang_arg("-D__ANDROID_API__=10000")
        // Our interface shims
        .header("src/sys/BinderBindings.h")
        .whitelist_type("android::c_interface::.*")
        .rustified_non_exhaustive_enum("android::c_interface::StatusCode")
        .rustified_non_exhaustive_enum("android::c_interface::ExceptionCode")
        .opaque_type("android::c_interface::BinderNative")
        .whitelist_type("RustObject")
        // Opaque types from binder NDK
        .whitelist_type("AStatus")
        .whitelist_type("AIBinder_Class")
        .whitelist_type("AIBinder")
        .whitelist_type("AIBinder_Weak")
        .whitelist_type("AIBinder_DeathRecipient")
        .whitelist_type("AParcel")
        .whitelist_type("binder_status_t")
        .whitelist_function(".*")
        .opaque_type("std::.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .derive_debug(false)
        .generate()
        .expect("Bindgen failed to generate bindings for libbinder");

    // write bindings
    let out_path = Path::new("src/sys/libbinder_bindings.rs");
    bindings.write_to_file(&out_path).unwrap_or_else(|_| {
        panic!(
            "Bindgen failed to writing bindings to {}",
            out_path.display()
        )
    });
}
