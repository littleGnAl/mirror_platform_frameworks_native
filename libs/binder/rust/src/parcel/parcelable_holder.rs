/*
 * Copyright (C) 2021 The Android Open Source Project
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

use crate::binder::Stability;
use crate::error::{Result, StatusCode};
use crate::parcel::{Deserialize, Parcel, Parcelable, Serialize, NON_NULL_PARCELABLE_FLAG};

use downcast_rs::{Downcast, impl_downcast};
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

trait AnyParcelable: Downcast + Parcelable {}
impl_downcast!(AnyParcelable);
impl<T: Downcast + Parcelable> AnyParcelable for T {}

#[derive(Debug)]
enum ParcelableHolderData {
    Empty,
    Parcelable {
        parcelable: Rc<dyn AnyParcelable>,
        name: String,
    },
    Parcel(Parcel),
}

/// A container that can hold any arbitrary `Parcelable`.
///
/// This type is currently used for AIDL parcelable fields.
#[derive(Debug)]
pub struct ParcelableHolder {
    data: RefCell<ParcelableHolderData>,
    stability: Stability,
}

impl ParcelableHolder {
    /// Construct a new `ParcelableHolder` with the given stability.
    pub fn new(stability: Stability) -> Self {
        Self {
            data: RefCell::new(ParcelableHolderData::Empty),
            stability,
        }
    }

    /// Reset the contents of this `ParcelableHolder`.
    ///
    /// Note that this method does not reset the stability,
    /// only the contents.
    pub fn reset(&mut self) {
        *self.data.get_mut() = ParcelableHolderData::Empty;
        // We could also clear stability here, but C++ doesn't
    }

    /// Set the parcelable contained in this `ParcelableHolder`.
    pub fn set_parcelable<T: Any + Parcelable + std::fmt::Debug>(
        &mut self,
        p: Option<Rc<T>>,
    ) -> Result<()> {
        if let Some(p) = p {
            if self.stability > p.get_stability() {
                return Err(StatusCode::BAD_VALUE);
            }

            *self.data.get_mut() = ParcelableHolderData::Parcelable {
                parcelable: p,
                name: <T as Parcelable>::get_descriptor().into(),
            };
        } else {
            *self.data.get_mut() = ParcelableHolderData::Empty;
        }

        Ok(())
    }

    /// Retrieve the parcelable stored in this `ParcelableHolder`.
    ///
    /// This method attempts to retrieve the parcelable inside
    /// the current object as a parcelable of type `T`.
    /// The object is validated against `T` by checking that
    /// its parcelable descriptor matches the one returned
    /// by `T::get_descriptor()`.
    ///
    /// Returns one of the following:
    /// * `Err(_)` in case of error
    /// * `Ok(None)` if the holder is empty or the descriptor does not match
    /// * `Ok(Some(_))` if the object holds a parcelable of type `T`
    ///   with the correct descriptor
    pub fn get_parcelable<T: Any + Parcelable + Default>(
        &self,
    ) -> Result<Option<Rc<T>>> {
        let parcelable_desc = <T as Parcelable>::get_descriptor();
        let mut data = self.data.borrow_mut();
        match *data {
            ParcelableHolderData::Empty => Ok(None),
            ParcelableHolderData::Parcelable { ref parcelable, ref name } => {
                if name != parcelable_desc {
                    return Err(StatusCode::BAD_VALUE);
                }

                match Rc::clone(parcelable).downcast_rc::<T>() {
                    Err(_) => Err(StatusCode::BAD_VALUE),
                    Ok(x) => Ok(Some(x)),
                }
            }
            ParcelableHolderData::Parcel(ref parcel) => {
                unsafe {
                    // Safety: 0 should always be a valid position.
                    parcel.set_data_position(0)?;
                }

                let name: String = parcel.read()?;
                if name != parcelable_desc {
                    return Ok(None);
                }

                let mut parcelable = T::default();
                parcelable.deserialize_parcelable(parcel)?;

                let parcelable = Rc::new(parcelable);
                let result = Rc::clone(&parcelable);
                *data = ParcelableHolderData::Parcelable {
                    parcelable,
                    name,
                };

                Ok(Some(result))
            }
        }
    }

    /// Return the stability value of this object.
    pub fn get_stability(&self) -> Stability {
        self.stability
    }
}

impl Clone for ParcelableHolder {
    fn clone(&self) -> Self {
        let new_data = match *self.data.borrow() {
            ParcelableHolderData::Empty => ParcelableHolderData::Empty,
            ParcelableHolderData::Parcelable { ref parcelable, ref name } => {
                ParcelableHolderData::Parcelable {
                    parcelable: parcelable.clone(),
                    name: name.clone(),
                }
            }
            ParcelableHolderData::Parcel(ref parcel) => {
                let mut new_parcel = Parcel::try_new()
                    .expect("Failed to allocate parcel");
                new_parcel.append_all_from(parcel)
                    .expect("Failed to append from Parcel");
                ParcelableHolderData::Parcel(new_parcel)
            }
        };

        Self {
            data: RefCell::new(new_data),
            stability: self.stability,
        }
    }
}

impl Serialize for ParcelableHolder {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
        parcel.write(&self.stability)?;

        match *self.data.borrow() {
            ParcelableHolderData::Empty => {
                parcel.write(&0i32)
            }
            ParcelableHolderData::Parcelable { ref parcelable, ref name } => {
                parcel.sized_write(/*include_length*/ false, |subparcel| {
                    subparcel.write(name)?;
                    subparcel.write_parcelable(&**parcelable)
                })
            }
            ParcelableHolderData::Parcel(ref p) => {
                parcel.write(&p.get_data_size())?;
                parcel.append_all_from(p)
            }
        }
    }
}

impl Deserialize for ParcelableHolder {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let present: i32 = parcel.read()?;
        if present != NON_NULL_PARCELABLE_FLAG {
            return Err(StatusCode::UNEXPECTED_NULL);
        }

        let stability = parcel.read()?;

        let data_size: i32 = parcel.read()?;
        if data_size < 0 {
            // C++ returns BAD_VALUE here,
            // while Java returns ILLEGAL_ARGUMENT
            return Err(StatusCode::BAD_VALUE);
        }
        if data_size == 0 {
            return Ok(Self {
                data: RefCell::new(ParcelableHolderData::Empty),
                stability,
            });
        }

        // TODO: C++ ParcelableHolder accepts sizes up to SIZE_MAX here, but we
        // only go up to i32::MAX because that's what our API uses everywhere
        let data_start = parcel.get_data_position();
        let data_end = data_start.checked_add(data_size)
            .ok_or(StatusCode::BAD_VALUE)?;

        let mut new_parcel = Parcel::try_new()
            .ok_or(StatusCode::NO_MEMORY)?;
        new_parcel.append_from(parcel, data_start, data_size)?;
        unsafe {
            // Safety: `append_from` checks if `data_size` overflows
            // `parcel` and returns `BAD_VALUE` if that happens. We also
            // explicitly check for negative and zero `data_size` above,
            // so `data_end` is guaranteed to be greater than `data_start`.
            parcel.set_data_position(data_end)?;
        }

        Ok(Self {
            data: RefCell::new(ParcelableHolderData::Parcel(new_parcel)),
            stability,
        })
    }
}
