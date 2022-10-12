/*
 * Copyright (C) 2022 The Android Open Source Project
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

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    improper_ctypes,
    missing_docs,
    clippy::all
)]

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use binder::binder_impl::Parcel;
use binder::unstable_api::AParcel;
use binder::unstable_api::AsNative;
use bindings::createRandomParcel;
use std::os::raw::c_void;

/// This API creates a random parcel to be used by fuzzers
pub fn create_random_parcel(fuzzer_data: &[u8]) -> Parcel {
    let mut parcel = Parcel::new();
    let aparcel_ptr: *mut AParcel = parcel.as_native_mut();
    unsafe {
        // Safety: `Parcel::as_native_mut` and `slice::as_ptr` always
        // return valid pointers.
        createRandomParcel(aparcel_ptr, fuzzer_data.as_ptr(), fuzzer_data.len());
    }
    parcel
}
