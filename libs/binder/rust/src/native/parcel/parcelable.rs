use crate::error::{BinderError, BinderResult};
use crate::native::parcel::Parcel;
use crate::native::utils::String8;
use crate::native::String16;

use std::convert::TryInto;

// Might be able to hook this up as a serde backend in the future
pub trait Parcelable {
    type Deserialized;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()>;
    fn deserialize(parcel: &Parcel) -> BinderResult<Self::Deserialized>;
}

impl Parcelable for bool {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_bool(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_bool()
    }
}

impl Parcelable for u8 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_i8(*self as i8)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_i8().map(|int8| int8 as u8)
    }
}

impl Parcelable for i8 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_i8(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_i8()
    }
}

impl Parcelable for u16 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_u16(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_u16()
    }
}

// REVIEW: No methods for i16?
// impl Parcelable for i16 {
//     fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
//         parcel.writeInt16(*self)
//     }

//     fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
//         parcel.try_readInt16()
//     }
// }

impl Parcelable for u32 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_u32(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_u32()
    }
}

impl Parcelable for i32 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_i32(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_i32()
    }
}

impl Parcelable for i64 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_i64(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_i64()
    }
}

impl Parcelable for u64 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_u64(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_u64()
    }
}

impl Parcelable for f32 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_f32(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_f32()
    }
}

impl Parcelable for f64 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_f64(*self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_f64()
    }
}

impl Parcelable for String8 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_string8(self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_string8()
    }
}

impl Parcelable for String16 {
    type Deserialized = Self;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        unsafe { parcel.write_string16(self) }
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
        parcel.try_read_string16()
    }
}

impl Parcelable for [u8] {
    type Deserialized = Vec<u8>;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_u8_slice(self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Vec<u8>> {
        let new_len = parcel
            .try_read_i32()?
            .try_into()
            .map_err(|_| BinderError::BAD_VALUE)?;
        let mut vec = Vec::new();

        vec.resize(new_len, 0);

        parcel.read_to_bytes(&mut vec)?;

        Ok(vec)
    }
}

impl Parcelable for [i32] {
    type Deserialized = Vec<i32>;

    fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
        parcel.write_i32_slice(self)
    }

    fn deserialize(parcel: &Parcel) -> BinderResult<Vec<i32>> {
        panic!("No deserialize method exists for i32 arrays")
    }
}

#[test]
fn test_custom_parcelable() {
    struct Custom(u32, bool, String8);

    impl Parcelable for Custom {
        type Deserialized = Self;

        fn serialize(&self, parcel: &mut Parcel) -> BinderResult<()> {
            self.0.serialize(parcel)?;
            self.1.serialize(parcel)?;
            self.2.serialize(parcel)
        }

        fn deserialize(parcel: &Parcel) -> BinderResult<Self> {
            Ok(Custom(
                parcel.try_read::<u32>()?,
                parcel.try_read::<bool>()?,
                parcel.try_read::<String8>()?,
            ))
        }
    }

    let mut string8 = String8::new();

    assert!(string8.append_bytes(b"Custom Parcelable").is_ok());

    let custom = Custom(123_456_789, true, string8);

    let mut parcel = Parcel::new();

    assert!(custom.serialize(&mut parcel).is_ok());
    assert_eq!(parcel.data_size(), 32);

    assert!(parcel.set_data_position(0).is_ok());

    let custom2 = Custom::deserialize(&parcel).unwrap();

    assert_eq!(custom2.0, 123_456_789);
    assert!(custom2.1);
    assert_eq!(custom2.2, custom.2);
}

#[test]
fn test_slice_parcelables() {
    let u8s = [101u8, 255, 42, 117];

    let mut parcel = Parcel::new();

    assert!(u8s.serialize(&mut parcel).is_ok());

    assert_eq!(parcel.data_position(), 8);

    assert!(parcel.set_data_position(0).is_ok());

    assert_eq!(parcel.data(), [4, 0, 0, 0, 101, 255, 42, 117]);

    let vec = <[u8]>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [101, 255, 42, 117]);
}
