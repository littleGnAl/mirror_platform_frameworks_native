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

use crate::error::{Error, Result};
use super::{Deserialize, Parcel, Serialize};

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd};

/// Rust version of the Java class android.os.ParcelFileDescriptor
pub struct ParcelFileDescriptor(File);

impl ParcelFileDescriptor {
    pub fn new(file: File) -> Self {
        Self(file)
    }
}

impl AsRef<File> for ParcelFileDescriptor {
    fn as_ref(&self) -> &File {
        &self.0
    }
}

impl From<ParcelFileDescriptor> for File {
    fn from(file: ParcelFileDescriptor) -> File {
        file.0
    }
}

impl Serialize for ParcelFileDescriptor {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        unsafe { parcel.write_dup_parcel_file_descriptor(self.0.as_raw_fd()) }
    }
}

impl Deserialize for ParcelFileDescriptor {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let fd = unsafe { parcel.read_parcel_file_descriptor()? };
        // We don't own this file and should not close it here, so we forget it
        // instead of dropping it.
        let file = unsafe { File::from_raw_fd(fd) };
        let file_dup = file.try_clone().map_err(|_| Error::BAD_VALUE);
        mem::forget(file);
        file_dup.map(ParcelFileDescriptor::new)
    }
}
