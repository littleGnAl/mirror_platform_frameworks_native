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

use arbitrary::Unstructured;
use binder::binder_impl::{Parcel, Stability};
use binder::{ParcelFileDescriptor, Parcelable, ParcelableHolder, SpIBinder};
use binderReadParcelIface::aidl::EmptyParcelable::EmptyParcelable;
use binderReadParcelIface::aidl::GenericDataParcelable::GenericDataParcelable;
use binderReadParcelIface::aidl::SingleDataParcelable::SingleDataParcelable;

macro_rules! read_parcel_interface {
    ($data_type:ty) => {
        |(parcel, _data)| {
            let _res = parcel.read::<$data_type>();
        }
    };
}

#[derive(Debug, Default)]
pub struct SomeParcelable {
    pub data: i32,
}

impl binder::Parcelable for SomeParcelable {
    fn write_to_parcel(
        &self,
        parcel: &mut binder::binder_impl::BorrowedParcel,
    ) -> std::result::Result<(), binder::StatusCode> {
        parcel.sized_write(|subparcel| {
            subparcel.write(&self.data)?;
            Ok(())
        })
    }

    fn read_from_parcel(
        &mut self,
        parcel: &binder::binder_impl::BorrowedParcel,
    ) -> std::result::Result<(), binder::StatusCode> {
        parcel.sized_read(|subparcel| {
            if subparcel.has_more_data() {
                self.data = subparcel.read()?;
            }
            Ok(())
        })
    }
}

binder::impl_deserialize_for_parcelable!(SomeParcelable);

pub fn get_read_funcs() -> Vec<Box<dyn Fn((Parcel, &[u8]))>> {
    let read_funcs: Vec<Box<dyn Fn((Parcel, &[u8]))>> = vec![
        Box::new(|(parcel, data)| {
            let mut u = Unstructured::new(data);
            let pos: i32 = u.int_in_range(0..=i32::MAX).unwrap_or(0);
            unsafe {
                // Safety: Safe if pos is less than current size of the parcel.
                // It relies on C++ code for bound checks
                match parcel.set_data_position(pos) {
                    Ok(result) => result,
                    Err(e) => println!("error occurred while setting data position: {:?}", e),
                }
            }
        }),
        Box::new(|(parcel, _data)| {
            let data_size = parcel.get_data_size();
            println!("data size from parcel: {:?}", data_size);
        }),
        Box::new(|(parcel, data)| {
            let mut u = Unstructured::new(data);
            let stability_val = u.int_in_range(0..=1).unwrap_or(0);
            let stability: Stability =
                Stability::try_from(stability_val).unwrap_or(Stability::Local);
            let mut holder: ParcelableHolder = ParcelableHolder::new(stability);
            match holder.read_from_parcel(parcel.borrowed_ref()) {
                Ok(result) => result,
                Err(e) => {
                    println!(
                        "ParcelableHolder: error occurred while reading from a parcel: {:?}",
                        e
                    )
                }
            }
        }),
        //read basic types
        Box::new(read_parcel_interface!(bool)),
        Box::new(read_parcel_interface!(i8)),
        Box::new(read_parcel_interface!(i32)),
        Box::new(read_parcel_interface!(i64)),
        Box::new(read_parcel_interface!(f32)),
        Box::new(read_parcel_interface!(f64)),
        Box::new(read_parcel_interface!(u16)),
        Box::new(read_parcel_interface!(u32)),
        Box::new(read_parcel_interface!(u64)),
        Box::new(read_parcel_interface!(String)),
        //read vec of basic types
        Box::new(read_parcel_interface!(Vec<i8>)),
        Box::new(read_parcel_interface!(Vec<i32>)),
        Box::new(read_parcel_interface!(Vec<i64>)),
        Box::new(read_parcel_interface!(Vec<f32>)),
        Box::new(read_parcel_interface!(Vec<f64>)),
        Box::new(read_parcel_interface!(Vec<u16>)),
        Box::new(read_parcel_interface!(Vec<u32>)),
        Box::new(read_parcel_interface!(Vec<u64>)),
        Box::new(read_parcel_interface!(Vec<String>)),
        Box::new(read_parcel_interface!(Option<Vec<i8>>)),
        Box::new(read_parcel_interface!(Option<Vec<i32>>)),
        Box::new(read_parcel_interface!(Option<Vec<i64>>)),
        Box::new(read_parcel_interface!(Option<Vec<f32>>)),
        Box::new(read_parcel_interface!(Option<Vec<f64>>)),
        Box::new(read_parcel_interface!(Option<Vec<u16>>)),
        Box::new(read_parcel_interface!(Option<Vec<u32>>)),
        Box::new(read_parcel_interface!(Option<Vec<u64>>)),
        Box::new(read_parcel_interface!(Option<Vec<String>>)),
        Box::new(read_parcel_interface!(ParcelFileDescriptor)),
        Box::new(read_parcel_interface!(Vec<Option<ParcelFileDescriptor>>)),
        Box::new(read_parcel_interface!(Option<Vec<ParcelFileDescriptor>>)),
        Box::new(read_parcel_interface!(Option<Vec<Option<ParcelFileDescriptor>>>)),
        Box::new(read_parcel_interface!(SpIBinder)),
        Box::new(read_parcel_interface!(Vec<Option<SpIBinder>>)),
        Box::new(read_parcel_interface!(Option<Vec<SpIBinder>>)),
        Box::new(read_parcel_interface!(Option<Vec<Option<SpIBinder>>>)),
        Box::new(read_parcel_interface!(SomeParcelable)),
        Box::new(read_parcel_interface!(Vec<Option<SomeParcelable>>)),
        Box::new(read_parcel_interface!(Option<Vec<SomeParcelable>>)),
        Box::new(read_parcel_interface!(Option<Vec<Option<SomeParcelable>>>)),
        // Fuzz read_from_parcel for AIDL generated parcelables
        Box::new(|(parcel, _data)| {
            let mut empty_parcelable: EmptyParcelable = EmptyParcelable::default();
            match empty_parcelable.read_from_parcel(parcel.borrowed_ref()) {
                Ok(result) => result,
                Err(e) => {
                    println!("EmptyParcelable: error occurred while reading from a parcel: {:?}", e)
                }
            }
        }),
        Box::new(|(parcel, _data)| {
            let mut single_parcelable: SingleDataParcelable = SingleDataParcelable::default();
            match single_parcelable.read_from_parcel(parcel.borrowed_ref()) {
                Ok(result) => result,
                Err(e) => println!(
                    "SingleDataParcelable: error occurred while reading from a parcel: {:?}",
                    e
                ),
            }
        }),
        Box::new(|(parcel, _data)| {
            let mut generic_parcelable: GenericDataParcelable = GenericDataParcelable::default();
            match generic_parcelable.read_from_parcel(parcel.borrowed_ref()) {
                Ok(result) => result,
                Err(e) => println!(
                    "GenericDataParcelable: error occurred while reading from a parcel: {:?}",
                    e
                ),
            }
        }),
    ];

    read_funcs
}
