/*
 * Copyright (C) 2023 The Android Open Source Project
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

use crate::error::{Result, StatusCode};
use crate::parcel::{
    BorrowedParcel, Deserialize, DeserializeArray, DeserializeOption, Serialize, SerializeArray,
    SerializeOption,
};

/// Rust version of the Java class android.os.ParcelFileDescriptor
#[derive(Debug, PartialEq, Eq)]
pub struct ParcelFileDescriptor;

impl Serialize for ParcelFileDescriptor {
    fn serialize(&self, _parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        // TODO(b/242940548): implement support for Trusty handles
        Err(StatusCode::FDS_NOT_ALLOWED)
    }
}

impl SerializeArray for ParcelFileDescriptor {}

impl SerializeOption for ParcelFileDescriptor {
    fn serialize_option(_this: Option<&Self>, _parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        Err(StatusCode::FDS_NOT_ALLOWED)
    }
}

impl DeserializeOption for ParcelFileDescriptor {
    fn deserialize_option(_parcel: &BorrowedParcel<'_>) -> Result<Option<Self>> {
        Err(StatusCode::FDS_NOT_ALLOWED)
    }
}

impl Deserialize for ParcelFileDescriptor {
    type UninitType = ();
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(_value: Self) -> Self::UninitType {
        ()
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        Deserialize::deserialize(parcel).transpose().unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeArray for ParcelFileDescriptor {}
