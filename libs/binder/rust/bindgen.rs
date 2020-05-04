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

use std::env;
use std::io;

fn main() {
    let mut bindings = bindgen::Builder::default()
        .clang_args(&["-x", "c++"])
        .clang_arg("-std=gnu++17")
        // Avoid some checked casts because we know uintptr_t == size_t. This
        // property is enforced by a static assert in the bindings header.
        .size_t_is_usize(true)
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
        .opaque_type("android::wp")
        .opaque_type("android::Vector")
        .opaque_type("std::.*")
        // We provide our own sp definition
        .blacklist_type("android::sp")
        // We don't want to ever see these types, as they should not be exposed
        .blacklist_type("android::Parcel_Blob")
        .blacklist_function("android::Parcel_Blob.*")
        .blacklist_type("android::Parcel_Flattenable.*")
        .blacklist_type("android::ProcessState_handle_entry")
        .blacklist_type("android::RefBase.*")
        .blacklist_function("android::RefBase.*")
        .blacklist_type("android::wp_weakref_type")
        .blacklist_function("android::binder::Status_exceptionToString")
        .derive_debug(false);

    // Skip over executable
    let mut args = env::args().skip(1);
    loop {
        if let Some(arg) = args.next() {
            if arg == "--" {
                break;
            }
            bindings = bindings.header(arg);
        } else {
            break;
        }
    }

    for arg in args {
        bindings = bindings.clang_arg(arg);
    }

    println!("#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]");
    println!("#[repr(C)]");
    println!("pub struct android_sp<T> {{");
    println!("    _opaque: [u8; 0],");
    println!("    _phantom: std::marker::PhantomData<T>,");
    println!("}}\n");

    // TODO: Remove when rust-bindgen >= 0.53.2 is available in external/
    println!("fn android_binder_Status_exceptionToString(_: android_status_t) -> std_string {{");
    println!("    unreachable!(\"Temporary workaround until a version of rust-bindgen with commit ee2f289a2d57e4d67fe38d060f0c93e9ab866183 is released\");");
    println!("}}\n");

    bindings.generate()
        .expect("Bindgen failed to generate bindings for libbinder")
        .write(Box::new(io::stdout()))
        .expect("Failed to write bindings to standard out");
}
