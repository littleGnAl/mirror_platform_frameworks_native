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

use binder::binder_impl::Parcel;
use binder::unstable_api::{AParcel, AsNative};
use binder::SpIBinder;
use binder_random_parcel_bindgen::{createRandomParcel, fuzzRustService};
use std::os::raw::c_void;

/// This API creates a random parcel to be used by fuzzers
pub fn create_random_parcel(fuzzer_data: &[u8]) -> Parcel {
    let mut parcel = Parcel::new();
    let aparcel_ptr: *mut AParcel = parcel.as_native_mut();
    let ptr = aparcel_ptr as *mut c_void;
    unsafe {
        // Safety: `Parcel::as_native_mut` and `slice::as_ptr` always
        // return valid pointers.
        createRandomParcel(ptr, fuzzer_data.as_ptr(), fuzzer_data.len());
    }
    parcel
}

/// This API automatically fuzzes provided service
pub fn fuzz_service(mut binder: SpIBinder, fuzzer_data: &[u8]) {
    let ptr = binder.as_native_mut() as *mut c_void;
    unsafe {
        // Safety: `SpIBinder::as_native_mut` and `slice::as_ptr` always
        // return valid pointers.
        fuzzRustService(ptr, fuzzer_data.as_ptr(), fuzzer_data.len());
    }
}
