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
        .clang_arg("-I../include")
        .clang_arg("-I../../../../../system/core/libutils/include")
        .clang_arg("-I../../../../../system/core/liblog/include")
        .clang_arg("-I../../../../../system/core/libsystem/include")
        .clang_arg("-I../../../../../system/core/base/include")
        .clang_arg("-I../../../../../system/core/libcutils/include")
        .clang_args(&["-x", "c++"])
        .clang_arg("-std=gnu++17")
        // Our interface shims
        .header("src/sys/BinderBindings.h")
        .whitelist_function("android::c_interface::.*")
        .whitelist_type("android::c_interface::Error")
        .rustified_non_exhaustive_enum("android::c_interface::Error")
        .opaque_type("android::c_interface::BinderNative")
        // Simple types we can export from C++. Make sure these types are ALL
        // POD.
        .whitelist_type("android::status_t")
        .whitelist_type("android::TransactionCode")
        .whitelist_type("android::TransactionFlags")
        .whitelist_type("android::binder::Status")
        .whitelist_type("binder_size_t")
        // Types used as opaque pointers from C++
        .opaque_type("android::BBinder")
        .opaque_type("android::BpBinder")
        .opaque_type("android::IBinder")
        .opaque_type("android::IBinder_DeathRecipient")
        .opaque_type("android::IPCThreadState")
        .opaque_type("android::IInterface")
        .opaque_type("android::IServiceManager")
        // WARNING We allocate Parcel on the Rust side, so it must be correctly
        // sized.
        .opaque_type("android::Parcel")
        .opaque_type("android::Parcel_ReadableBlob")
        .opaque_type("android::Parcel_WritableBlob")
        .opaque_type("android::Parcelable")
        .opaque_type("android::ProcessState")
        .opaque_type("android::String8")
        .opaque_type("android::String16")
        .opaque_type("android::thread_id_t")
        .opaque_type("android::Vector")
        .opaque_type("std::.*")
        // We provide our own definitions
        .blacklist_type("android::sp")
        .blacklist_type("android::wp")
        // We don't want to ever see these types, as they should not be exposed
        .blacklist_type("android::Parcel_Blob")
        .blacklist_function("android::Parcel_Blob.*")
        .blacklist_type("android::Parcel_Flattenable.*")
        .blacklist_type("android::ProcessState_handle_entry")
        .blacklist_type("android::RefBase.*")
        .blacklist_function("android::RefBase.*")
        .blacklist_type("android::wp_weakref_type")
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
