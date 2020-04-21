extern crate bindgen;

use std::env;
use std::io;

fn main() {
    let mut bindings = bindgen::Builder::default()
        .clang_args(&["-x", "c++"])
        .clang_arg("-std=gnu++17")
        .whitelist_function("cxx_timing::.*")
        .opaque_type("std::.*")
        .enable_cxx_namespaces()
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

    println!("pub use root::cxx_timing;");

    bindings.generate()
        .expect("Bindgen failed to generate bindings for libbinder")
        .write(Box::new(io::stdout()))
        .expect("Failed to write bindings to standard out");
}
