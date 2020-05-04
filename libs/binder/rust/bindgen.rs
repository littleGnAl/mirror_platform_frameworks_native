extern crate bindgen;

use std::env;
use std::io;

fn main() {
    let mut bindings = bindgen::Builder::default()
        .clang_args(&["-x", "c++"])
        .clang_arg("-std=gnu++17")
        .whitelist_function("android::c_interface::.*")
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

    println!("#[repr(C)]");
    println!("pub struct android_sp<T> {{");
    println!("    _opaque: [u8; 0],");
    println!("    _phantom: std::marker::PhantomData<T>,");
    println!("}}\n");

    bindings.generate()
        .expect("Bindgen failed to generate bindings for libbinder")
        .write(Box::new(io::stdout()))
        .expect("Failed to write bindings to standard out");
}
