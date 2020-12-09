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

//! Generated Rust bindings to libbinder_ndk

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    improper_ctypes,
    missing_docs
)]

use std::error;
use std::fmt;

pub use binder_ndk_bindgen::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum StatusCode  {
    OK = android_c_interface_StatusCode::OK as isize,
    UNKNOWN_ERROR = android_c_interface_StatusCode::UNKNOWN_ERROR as isize,
    NO_MEMORY = android_c_interface_StatusCode::NO_MEMORY as isize,
    INVALID_OPERATION = android_c_interface_StatusCode::INVALID_OPERATION as isize,
    BAD_VALUE = android_c_interface_StatusCode::BAD_VALUE as isize,
    BAD_TYPE = android_c_interface_StatusCode::BAD_TYPE as isize,
    NAME_NOT_FOUND = android_c_interface_StatusCode::NAME_NOT_FOUND as isize,
    PERMISSION_DENIED = android_c_interface_StatusCode::PERMISSION_DENIED as isize,
    NO_INIT = android_c_interface_StatusCode::NO_INIT as isize,
    ALREADY_EXISTS = android_c_interface_StatusCode::ALREADY_EXISTS as isize,
    DEAD_OBJECT = android_c_interface_StatusCode::DEAD_OBJECT as isize,
    FAILED_TRANSACTION = android_c_interface_StatusCode::FAILED_TRANSACTION as isize,
    BAD_INDEX = android_c_interface_StatusCode::BAD_INDEX as isize,
    NOT_ENOUGH_DATA = android_c_interface_StatusCode::NOT_ENOUGH_DATA as isize,
    WOULD_BLOCK = android_c_interface_StatusCode::WOULD_BLOCK as isize,
    TIMED_OUT = android_c_interface_StatusCode::TIMED_OUT as isize,
    UNKNOWN_TRANSACTION = android_c_interface_StatusCode::UNKNOWN_TRANSACTION as isize,
    FDS_NOT_ALLOWED = android_c_interface_StatusCode::FDS_NOT_ALLOWED as isize,
    UNEXPECTED_NULL = android_c_interface_StatusCode::UNEXPECTED_NULL as isize,
}

impl error::Error for StatusCode {}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "StatusCode::{:?}", self)
    }
}
