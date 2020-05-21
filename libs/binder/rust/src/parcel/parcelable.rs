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
use crate::parcel::Parcel;
use crate::utils::{Str16, Str8, String16, String8};

use std::convert::TryInto;

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

impl Serialize for bool {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_bool(*self)
    }
}

impl Deserialize for bool {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_bool()
    }
}

// TODO: implement serialize for u8 and i8 once specialization is available in
// stable Rust. We need to specialize the vector serialization and
// deserialization for these types because byte vectors are packed in parcels.

impl Serialize for u16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_u16(*self)
    }
}

impl Deserialize for u16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_u16()
    }
}

impl Serialize for i16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i16(*self)
    }
}

impl Deserialize for i16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i16()
    }
}

impl Serialize for u32 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_u32(*self)
    }
}

impl Deserialize for u32 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_u32()
    }
}

impl Serialize for i32 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i32(*self)
    }
}

impl Deserialize for i32 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i32()
    }
}

impl Serialize for i64 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i64(*self)
    }
}

impl Deserialize for i64 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i64()
    }
}

impl Serialize for u64 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_u64(*self)
    }
}

impl Deserialize for u64 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_u64()
    }
}

impl Serialize for f32 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_f32(*self)
    }
}

impl Deserialize for f32 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_f32()
    }
}

impl Serialize for f64 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_f64(*self)
    }
}

impl Deserialize for f64 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_f64()
    }
}

impl Serialize for String8 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string8(self)
    }
}

impl Deserialize for String8 {
    fn deserialize(parcel: &Parcel) -> Result<String8> {
        parcel.read_string8()
    }
}

impl Serialize for &Str8 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string8(self)
    }
}

impl Serialize for String16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string16(self)
    }
}

impl Deserialize for String16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_string16()
    }
}

impl Serialize for &Str16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string16(self)
    }
}

impl<P: Serialize> Serialize for [P] {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice(self)
    }
}

impl<P: Default + Deserialize> Deserialize for Vec<P> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let mut vec = Vec::new();

        parcel.read_to_vec(&mut vec)?;

        Ok(vec)
    }
}

impl Deserialize for Vec<String8> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let size = parcel.read_i32()?;
        let mut vec = Vec::with_capacity(size.try_into().or(Err(Error::BAD_VALUE))?);

        for _ in 0..size {
            vec.push(parcel.read_string8()?);
        }

        Ok(vec)
    }
}

impl Deserialize for Vec<String16> {
    fn deserialize(parcel: &Parcel) -> Result<Vec<String16>> {
        let size = parcel.read_i32()?;
        let mut vec = Vec::with_capacity(size.try_into().or(Err(Error::BAD_VALUE))?);

        for _ in 0..size {
            vec.push(parcel.read_string16()?);
        }

        Ok(vec)
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
                parcel.read()?,
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

    assert!(parcel.write_u8_slice(&u8s).is_ok());

    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 101, 255, 42, 117]);

    let mut vec = Vec::new();

    parcel.read_byte_vec(&mut vec).unwrap();

    assert_eq!(vec, [101, 255, 42, 117]);

    let i8s = [-128i8, 127, 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(parcel.write_i8_slice(&i8s).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [
        4, 0, 0, 0, // 4 items:
        128, 127, 42, 139, // bytes
    ]);

    let mut vec: Vec<u8> = Vec::new();

    parcel.read_byte_vec(&mut vec).unwrap();

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
