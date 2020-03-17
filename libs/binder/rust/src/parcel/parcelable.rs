use crate::error::{Error, Result};
use crate::parcel::Parcel;
use crate::utils::{Str16, Str8, String16, String8};

use std::convert::TryInto;

/// A struct whose instances can be written to and restored from a
/// [`Parcel`].
// Might be able to hook this up as a serde backend in the future
pub trait Parcelable {
    /// The owned type this struct deserializes into.
    type Deserialized;

    /// Serialize this instance into the given [`Parcel`].
    fn serialize(&self, parcel: &mut Parcel) -> Result<()>;

    /// Deserialize an instance from the given [`Parcel`].
    fn deserialize(parcel: &Parcel) -> Result<Self::Deserialized>;
}

impl Parcelable for bool {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_bool(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_bool()
    }
}

impl Parcelable for u8 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i8(*self as i8)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        Ok(parcel.read_i8()? as u8)
    }
}

impl Parcelable for i8 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i8(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i8()
    }
}

impl Parcelable for u16 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_u16(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_u16()
    }
}

impl Parcelable for i16 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i16(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i16()
    }
}

impl Parcelable for u32 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_u32(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_u32()
    }
}

impl Parcelable for i32 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i32(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i32()
    }
}

impl Parcelable for i64 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_i64(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_i64()
    }
}

impl Parcelable for u64 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_u64(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_u64()
    }
}

impl Parcelable for f32 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_f32(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_f32()
    }
}

impl Parcelable for f64 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_f64(*self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_f64()
    }
}

impl Parcelable for String8 {
    type Deserialized = String8;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string8(self)
    }

    fn deserialize(parcel: &Parcel) -> Result<String8> {
        parcel.read_string8()
    }
}

impl Parcelable for &Str8 {
    type Deserialized = String8;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string8(self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self::Deserialized> {
        parcel.read_string8()
    }
}

impl Parcelable for String16 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string16(self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self> {
        parcel.read_string16()
    }
}

impl Parcelable for &Str16 {
    type Deserialized = String16;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_string16(self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Self::Deserialized> {
        parcel.read_string16()
    }
}

impl<P: Copy + Default + Parcelable> Parcelable for [P] {
    type Deserialized = Vec<P>;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice(self)
    }

    fn deserialize(parcel: &Parcel) -> Result<Vec<P>> {
        let mut vec = Vec::new();

        parcel.read_to_vec(&mut vec)?;

        Ok(vec)
    }
}

impl Parcelable for [String8] {
    type Deserialized = Vec<String8>;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice_size(self)?;

        for str8 in self {
            parcel.write_string8(str8)?;
        }

        Ok(())
    }

    fn deserialize(parcel: &Parcel) -> Result<Vec<String8>> {
        let size = parcel.read_i32()?;
        let mut vec = Vec::with_capacity(size.try_into().or(Err(Error::BAD_VALUE))?);

        for _ in 0..size {
            vec.push(parcel.read_string8()?);
        }

        Ok(vec)
    }
}

impl Parcelable for [&Str8] {
    type Deserialized = Vec<String8>;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice_size(self)?;

        for str8 in self {
            parcel.write_string8(str8)?;
        }

        Ok(())
    }

    fn deserialize(parcel: &Parcel) -> Result<Vec<String8>> {
        let size = parcel.read_i32()?;
        let mut vec = Vec::with_capacity(size.try_into().or(Err(Error::BAD_VALUE))?);

        for _ in 0..size {
            vec.push(parcel.read_string8()?);
        }

        Ok(vec)
    }
}

impl Parcelable for [String16] {
    type Deserialized = Vec<String16>;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice_size(self)?;

        for str16 in self {
            parcel.write_string16(str16)?;
        }

        Ok(())
    }

    fn deserialize(parcel: &Parcel) -> Result<Vec<String16>> {
        let size = parcel.read_i32()?;
        let mut vec = Vec::with_capacity(size.try_into().or(Err(Error::BAD_VALUE))?);

        for _ in 0..size {
            vec.push(parcel.read_string16()?);
        }

        Ok(vec)
    }
}

impl Parcelable for [&Str16] {
    type Deserialized = Vec<String16>;

    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_slice_size(self)?;

        for str16 in self {
            parcel.write_string16(str16)?;
        }

        Ok(())
    }

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

    impl Parcelable for Custom {
        type Deserialized = Self;

        fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
            self.0.serialize(parcel)?;
            self.1.serialize(parcel)?;
            self.2.serialize(parcel)?;
            self.3.serialize(parcel)
        }

        fn deserialize(parcel: &Parcel) -> Result<Self> {
            Ok(Custom(
                parcel.read::<u32>()?,
                parcel.read::<bool>()?,
                parcel.read::<String8>()?,
                parcel.read::<[String8]>()?,
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

    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 1, 0, 0, 1]);

    let vec = <[bool]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [true, false, false, true]);

    let u8s = [101u8, 255, 42, 117];

    let mut parcel = Parcel::new();

    assert!(u8s.serialize(&mut parcel).is_ok());

    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 101, 255, 42, 117]);

    let vec = <[u8]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [101, 255, 42, 117]);

    let i8s = [-128i8, 127, 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i8s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 128, 127, 42, 139]);

    let vec = <[i8]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [-128i8, 127, 42, -117]);

    let u16s = [u16::max_value(), 12_345, 42, 117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(u16s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [8, 0, 0, 0, 255, 255, 57, 48, 42, 0, 117, 0]);

    let vec = <[u16]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u16::max_value(), 12_345, 42, 117]);

    let i16s = [i16::max_value(), i16::min_value(), 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i16s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.data(),
        [8, 0, 0, 0, 255, 127, 0, 128, 42, 0, 139, 255]
    );

    let vec = <[i16]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i16::max_value(), i16::min_value(), 42, -117]);

    let u32s = [u32::max_value(), 12_345, 42, 117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(u32s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.data(),
        [16, 0, 0, 0, 255, 255, 255, 255, 57, 48, 0, 0, 42, 0, 0, 0, 117, 0, 0, 0]
    );

    let vec = <[u32]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u32::max_value(), 12_345, 42, 117]);

    let i32s = [i32::max_value(), i32::min_value(), 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i32s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(
        parcel.data(),
        [16, 0, 0, 0, 255, 255, 255, 127, 0, 0, 0, 128, 42, 0, 0, 0, 139, 255, 255, 255]
    );

    let vec = <[i32]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i32::max_value(), i32::min_value(), 42, -117]);

    let u64s = [u64::max_value(), 12_345, 42, 117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(u64s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = <[u64]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u64::max_value(), 12_345, 42, 117]);

    let i64s = [i64::max_value(), i64::min_value(), 42, -117];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(i64s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = <[i64]>::deserialize(&parcel).unwrap();

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

    let vec = <[f32]>::deserialize(&parcel).unwrap();

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

    let vec = <[f64]>::deserialize(&parcel).unwrap();

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

    let vec = <[String8]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, str8s);

    let s4 = "Hello, Binder!".into();
    let s5 = "This is a utf8 string.".into();
    let s6 = "Some more text here.".into();

    let str16s = [s4, s5, s6];

    assert!(parcel.set_data_position(0).is_ok());
    assert!(str16s.serialize(&mut parcel).is_ok());
    assert!(parcel.set_data_position(0).is_ok());

    let vec = <[String16]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, str16s);
}
