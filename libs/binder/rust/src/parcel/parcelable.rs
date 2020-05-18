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

use crate::error::{binder_status, Error, Result};
use crate::parcel::Parcel;
use crate::sys::{libbinder_bindings::*};
use crate::utils::{AsNative, Str16, Str8, String16, String8};

use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::mem::{self, MaybeUninit};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::ptr;

/// A struct whose instances can be written to a [`Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Serialize {
    /// Serialize this instance into the given [`Parcel`].
    fn serialize(&self, parcel: &mut Parcel) -> Result<()>;
}

/// A struct whose instances can be restored from a [`Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Deserialize: Sized {
    /// Deserialize an instance from the given [`Parcel`].
    fn deserialize(parcel: &Parcel) -> Result<Self>;
}

macro_rules! parcelable_primitives {
    {
        $(
            impl $trait:ident for $ty:ty = $fn:path;
        )*
    } => {
        $(impl_parcelable!{$trait, $ty, $fn})*
    };
}

macro_rules! impl_parcelable {
    {Serialize, $ty:ty, $write_fn:path} => {
        impl Serialize for $ty {
            fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
                unsafe { binder_status($write_fn(parcel.as_native_mut(), *self)) }
            }
        }
    };

    {Deserialize, $ty:ty, $read_fn:path} => {
        impl Deserialize for $ty {
            fn deserialize(parcel: &Parcel) -> Result<Self> {
                let mut val = Self::default();
                let status = unsafe { $read_fn(parcel.as_native(), &mut val) };

                match binder_status(status) {
                    Ok(()) => Ok(val),
                    Err(e) => Err(e),
                }
            }
        }
    };
}

parcelable_primitives! {
    impl Serialize for bool = android_Parcel_writeBool;
    impl Deserialize for bool = android_Parcel_readBool1;

    // We can't implement Serialize/Deserialize for byte-size types yet, because
    // (de-)serializing arrays of bytes requires special handling. Byte arrays
    // and vectors are packed, while single bytes are written as 32-bit
    // words. Since we implement Serialize for [S] and Deserialize for Vec<S>
    // using (De)Serialize for S, we would have a conflict between the
    // implementation of serializing a single byte vs serializing an array of
    // bytes. This can be fixed when the specialization feature is stabilized in
    // Rust (https://github.com/rust-lang/rust/issues/31844)

    // impl Serialize for i8 = android_Parcel_writeByte;
    // impl Deserialize for i8 = android_Parcel_readByte1;

    impl Serialize for u16 = android_Parcel_writeChar;
    impl Deserialize for u16 = android_Parcel_readChar1;

    impl Serialize for u32 = android_Parcel_writeUint32;
    impl Deserialize for u32 = android_Parcel_readUint321;

    impl Serialize for i32 = android_Parcel_writeInt32;
    impl Deserialize for i32 = android_Parcel_readInt321;

    impl Serialize for u64 = android_Parcel_writeUint64;
    impl Deserialize for u64 = android_Parcel_readUint641;

    impl Serialize for i64 = android_Parcel_writeInt64;
    impl Deserialize for i64 = android_Parcel_readInt641;

    impl Serialize for f32 = android_Parcel_writeFloat;
    impl Deserialize for f32 = android_Parcel_readFloat1;

    impl Serialize for f64 = android_Parcel_writeDouble;
    impl Deserialize for f64 = android_Parcel_readDouble1;
}

// TODO: implement serialize for u8 and i8 once specialization is available in
// stable Rust. We need to specialize the vector serialization and
// deserialization for these types because byte vectors are packed in parcels.

impl Serialize for i16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        (*self as u16).serialize(parcel)
    }
}

impl Deserialize for i16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        u16::deserialize(parcel).map(|v| v as i16)
    }
}

impl Serialize for CStr {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        // writeCString assumes that we pass a null-terminated C string pointer
        // with no nulls in the middle of the string. Rust guarantees exactly
        // that for a valid CStr instance.
        unsafe {
            binder_status(android_Parcel_writeCString(
                parcel.as_native_mut(),
                self.as_ptr(),
            ))
        }
    }
}

impl Serialize for String {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write(&*String16::from(self.as_str()))
   }
}

impl Deserialize for String {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_utf8_from_utf16()
    }
}

impl Serialize for str {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write(&*String16::from(self))
   }
}

impl Serialize for &str {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write(&*String16::from(*self))
   }
}

impl Serialize for String8 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        self.as_ref().serialize(parcel)
    }
}

impl Deserialize for String8 {
    fn deserialize(parcel: &Parcel) -> Result<String8> {
        let mut string = ptr::null_mut();
        let result =
            unsafe { android_c_interface_Parcel_readString8(parcel.as_native(), &mut string) };

        binder_status(result)?;

        if string.is_null() {
            // This should never happen, it means our interface code did not
            // allocate a new String8
            return Err(Error::NO_MEMORY);
        }

        let owned_str = unsafe { String8::from_raw(string) };
        Ok(owned_str)
    }
}

impl Serialize for Str8 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_writeString8(
                parcel.as_native_mut(),
                self.as_native(),
            ))
        }
    }
}

impl Serialize for String16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        self.as_ref().serialize(parcel)
    }
}

impl Deserialize for String16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let mut s = MaybeUninit::uninit();
        let status =
            unsafe { android_c_interface_Parcel_readString16(parcel.as_native(), s.as_mut_ptr()) };

        binder_status(status).map(|_| unsafe { String16::from_raw(s.assume_init()) })
    }
}

impl Serialize for Str16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        unsafe {
            binder_status(android_Parcel_writeString16(
                parcel.as_native_mut(),
                self.as_native(),
            ))
        }
    }
}

impl<T: Serialize> Serialize for [T] {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice_size(self)?;

        for item in self {
            parcel.write(item)?;
        }

        Ok(())
    }
}

impl Serialize for [u8] {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        let len = self.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeByteArray(
                parcel.as_native_mut(),
                len,
                self.as_ptr(),
            ))
        }
    }
}

impl Serialize for [i8] {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        let len = self.len().try_into().unwrap();

        unsafe {
            binder_status(android_Parcel_writeByteArray(
                parcel.as_native_mut(),
                len,
                self.as_ptr() as *const u8,
            ))
        }
    }
}

impl<P: Deserialize> Deserialize for Option<Vec<P>> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let len: i32 = parcel.read()?;
        if len < 0 {
            return Ok(None);
        }

        // TODO: Assumes that usize is at least 32 bits
        let mut vec = Vec::with_capacity(len as usize);

        for _ in 0..len {
            vec.push(parcel.read()?);
        }

        Ok(Some(vec))
    }
}

impl<P> Deserialize for Vec<P>
    where Option<Vec<P>>: Deserialize
{
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        <Option<Self>>::deserialize(parcel).map(|opt| opt.unwrap())
    }
}

impl Deserialize for Option<Vec<u8>> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let len: i32 = parcel.read()?;
        if len < 0 {
            return Ok(None);
        }

        let mut vec = Vec::with_capacity(len as usize);
        vec.resize(len as usize, 0);

        let status = unsafe {
            android_Parcel_read(
                parcel.as_native(),
                vec.as_mut_ptr() as *mut libc::c_void,
                len.try_into().unwrap(),
            )
        };
        binder_status(status)?;

        Ok(Some(vec))
    }
}

impl Serialize for File {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        unsafe { parcel.write_dup_file_descriptor(self.as_raw_fd()) }
    }
}

impl Deserialize for File {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        unsafe {
            let fd = parcel.read_file_descriptor()?;
            // We don't actually own this, so we CANNOT drop it
            let file = File::from_raw_fd(fd);
            let file_dup = file.try_clone().map_err(|_| Error::BAD_VALUE);
            mem::forget(file);
            file_dup
        }
    }
}

#[test]
fn test_custom_parcelable() {
    struct Custom(u32, bool, String8, Vec<String8>);

    impl Serialize for Custom {
        fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
            self.0.serialize(parcel)?;
            self.1.serialize(parcel)?;
            self.2.serialize(parcel)?;
            self.3.serialize(parcel)
        }
    }

    impl Deserialize for Custom {
        fn deserialize(parcel: &Parcel) -> Result<Self> {
            Ok(Custom(
                parcel.read()?,
                parcel.read()?,
                parcel.read()?,
                parcel.read::<Option<Vec<String8>>>()?.unwrap(),
            ))
        }
    }

    let string8 = String8::from("Custom Parcelable");

    let s1 = String8::from("str1");
    let s2 = String8::from("str2");
    let s3 = String8::from("str3");

    let str8s = vec![s1, s2, s3];

    let custom = Custom(123_456_789, true, string8, str8s);

    let mut parcel = Parcel::new();

    assert!(custom.serialize(&mut parcel).is_ok());
    assert_eq!(parcel.data_size(), 72);

    assert!(parcel.set_data_position(0).is_ok());

    let custom2 = Custom::deserialize(&parcel).unwrap();

    assert_eq!(custom2.0, 123_456_789);
    assert!(custom2.1);
    assert_eq!(custom2.2, custom.2);
    assert_eq!(custom2.3, custom.3);
}

#[test]
fn test_slice_parcelables() {
    let bools = [true, false, false, true];

    let mut parcel = Parcel::new();

    assert!(bools.serialize(&mut parcel).is_ok());

    assert_eq!(parcel.data_position(), 20);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);

    let vec = Vec::<bool>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [true, false, false, true]);

    let u8s = [101u8, 255, 42, 117];

    let mut parcel = Parcel::new();

    assert!(parcel.write(&u8s[..]).is_ok());

    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 101, 255, 42, 117]);

    let vec = Vec::<u8>::deserialize(&parcel).unwrap();
    assert_eq!(vec, [101, 255, 42, 117]);

    let i8s = [-128i8, 127, 42, -117];

    assert!(parcel.set_data_position(0).is_ok());

    assert!(parcel.write(&i8s[..]).is_ok());

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [
        4, 0, 0, 0, // 4 items:
        128, 127, 42, 139, // bytes
    ]);

    let vec = Vec::<u8>::deserialize(&parcel).unwrap();
    assert_eq!(vec, [-128i8 as u8, 127, 42, -117i8 as u8]);

    let u16s = [u16::max_value(), 12_345, 42, 117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(u16s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [
        4, 0, 0, 0, // 4 items:
        255, 255, 0, 0, // u16::max_value()
        57, 48, 0, 0, // 12,345
        42, 0, 0, 0, // 42
        117, 0, 0, 0, // 117
    ]);

    let vec = Vec::<u16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u16::max_value(), 12_345, 42, 117]);

    let i16s = [i16::max_value(), i16::min_value(), 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i16s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [
       4, 0, 0, 0, // 4 items:
       255, 127, 0, 0, // i16::max_value()
       0, 128, 0, 0, // i16::min_value()
       42, 0, 0, 0, // 42
       139, 255, 0, 0, // -117
    ]);

    let vec = Vec::<i16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i16::max_value(), i16::min_value(), 42, -117]);

    let u32s = [u32::max_value(), 12_345, 42, 117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(u32s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [
        4, 0, 0, 0, // 4 items:
        255, 255, 255, 255, // u32::max_value()
        57, 48, 0, 0, // 12,345
        42, 0, 0, 0, // 42
        117, 0, 0, 0, // -117
    ]);

    let vec = Vec::<u32>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u32::max_value(), 12_345, 42, 117]);

    let i32s = [i32::max_value(), i32::min_value(), 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i32s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [
        4, 0, 0, 0, // 4 items:
        255, 255, 255, 127, // i32::max_value()
        0, 0, 0, 128, // i32::min_value()
        42, 0, 0, 0, // 42
        139, 255, 255, 255, // -117
    ]);

    let vec = Vec::<i32>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i32::max_value(), i32::min_value(), 42, -117]);

    let u64s = [u64::max_value(), 12_345, 42, 117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(u64s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = Vec::<u64>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u64::max_value(), 12_345, 42, 117]);

    let i64s = [i64::max_value(), i64::min_value(), 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i64s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = Vec::<i64>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i64::max_value(), i64::min_value(), 42, -117]);

    let f32s = [
        std::f32::NAN,
        std::f32::INFINITY,
        1.23456789,
        std::f32::EPSILON,
    ];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(f32s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = Vec::<f32>::deserialize(&parcel).unwrap();

    // NAN != NAN so we can't use it in the assert_eq:
    assert!(vec[0].is_nan());
    assert_eq!(vec[1..], f32s[1..]);

    let f64s = [
        std::f64::NAN,
        std::f64::INFINITY,
        1.234567890123456789,
        std::f64::EPSILON,
    ];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(f64s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = Vec::<f64>::deserialize(&parcel).unwrap();

    // NAN != NAN so we can't use it in the assert_eq:
    assert!(vec[0].is_nan());
    assert_eq!(vec[1..], f64s[1..]);

    let s1 = String8::from("Hello, Binder!");
    let s2 = String8::from("This is a utf8 string.");
    let s3 = String8::from("Some more text here.");

    let str8s = [s1, s2, s3];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(str8s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = Vec::<String8>::deserialize(&parcel).unwrap();

    assert_eq!(vec, str8s);

    let s4 = "Hello, Binder!".into();
    let s5 = "This is a utf8 string.".into();
    let s6 = "Some more text here.".into();

    let str16s = [s4, s5, s6];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(str16s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = Vec::<String16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, str16s);
}
