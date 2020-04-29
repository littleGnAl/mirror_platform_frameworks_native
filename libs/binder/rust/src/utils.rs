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

use crate::error::{binder_status, Result};
use crate::sys::libbinder_bindings::*;

use std::any::type_name;
use std::convert::{AsRef, TryInto};
use std::fmt;
use std::ops;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

/// Trait for transparent Rust wrappers around android C++ native types.
///
/// The pointer return by this trait's methods should be immediately passed to
/// C++ and not stored by Rust. The pointer is valid only as long as the
/// underlying C++ object is alive, so users must be careful to take this into
/// account, as Rust cannot enforce this.
///
/// # Safety
///
/// For this trait to be a correct implementation, `T` must be a valid android
/// C++ type. Since we cannot constrain this via the type system, this trait is
/// marked as unsafe.
pub unsafe trait AsNative<T> {
    /// Return a pointer to the native version of `self`
    fn as_native(&self) -> *const T;

    /// Return a mutable pointer to the native version of `self`
    fn as_native_mut(&mut self) -> *mut T;
}

/// Wrapper around the android strong reference-counted pointer.
///
/// Note: because this wrapper is generic, we cannot implement Drop that
/// decrements the ref count, because we would need to specialize on T in order
/// to call the right C++ function depending on the generic type. It is up to
/// users of `Sp` to properly decrement the pointer on drop if necessary.
#[repr(transparent)]
pub struct Sp<T>(pub(super) *mut android_sp<T>);

unsafe impl<T> AsNative<android_sp<T>> for Sp<T> {
    fn as_native(&self) -> *const android_sp<T> {
        self.0
    }

    fn as_native_mut(&mut self) -> *mut android_sp<T> {
        self.0
    }
}

impl<T> PartialEq for Sp<T>
where
    Sp<T>: AsNative<T>,
{
    fn eq(&self, other: &Self) -> bool {
        ptr::eq::<T>(self.as_native(), other.as_native())
    }
}

/// Construct a Rust wrapper type that contains a C++ strong pointer of the
/// given pointee type `$T`.
///
/// Various C++ accessors functions can be exposed by setting special "fields"
/// of the struct declaration. For example, `getter:
/// android_c_interface_Sp_getIBinder` will cause the wrapper type to implement
/// `AsNative`, exposing a native pointer to the pointee type by calling the
/// getter function. The `getter` accessor is always required and must be first;
/// subsequent accessors are optional and may appear in any order.
///
/// Available accessors and the corresponding C++ function declarations:
/// - `getter`: `T* getter(sp<T> *);` *(required)*
///
///   Get the raw pointer out of the `sp`. Implements the `AsNative` trait for
///   the wrapper, which is required.
///
/// - `clone`: sp<T>* clone(sp<T> *);
///
///   Clone the `sp`, returning a pointer to a new `sp`, leaving the original
///   strong reference untouched. Implements the `Clone` trait for the wrapper.
///
/// - `destructor`: void destructor(sp<T> *);
///
///   Delete this strong pointer reference. Implements the `Drop` trait for the
///   wrapper.
///
/// - `strong_count`: int32_t strong_count(const sp<T> *);
///
///   Get the number of strong references to this object. Adds a `strong_count`
///   method to the wrapper.
///
/// # Examples
///
/// ```rust
/// wrap_sp! {
///    /// Rust wrapper around Binder remote objects.
///    pub struct Interface(Sp<android_IBinder>) {
///        getter: android_c_interface_Sp_getIBinder,
///        destructor: android_c_interface_Sp_DropIBinder,
///        clone: android_c_interface_Sp_CloneIBinder,
///        strong_count: android_c_interface_Sp_StrongCountIBinder,
///    }
/// }
/// ```
macro_rules! wrap_sp {
    {
        $(#[$attr:meta])*
        $vis:vis struct $wrapper:ident(Sp<$T:ty>) {
            getter: $cxx_getter:path,
            $($accessor_name:ident: $accessor:path,)*
        }
    } => {
        $(#[$attr])*
        #[repr(transparent)]
        #[derive(PartialEq)]
        $vis struct $wrapper(crate::utils::Sp<$T>);

        impl $wrapper {
            pub(crate) unsafe fn from_raw(ptr: *mut android_sp<$T>) -> Option<Self> {
                if ptr.is_null() {
                    return None;
                }

                let sp = Sp(ptr.as_mut()?);
                let null_pointee = AsNative::<$T>::as_native(&sp).is_null();

                // We always need to construct the wrapper before we return so that its
                // destructor is called.
                let wrapper = Self(sp);

                if null_pointee {
                    None
                    // wrapper is dropped here, triggering its destructor if any
                } else {
                    Some(wrapper)
                }
            }
        }

        unsafe impl crate::utils::AsNative<$T> for Sp<$T> {
            fn as_native(&self) -> *const $T {
                if self.0.is_null() {
                    ptr::null()
                } else {
                    unsafe { $cxx_getter(self.0) }
                }
            }

            fn as_native_mut(&mut self) -> *mut $T {
                if self.0.is_null() {
                    ptr::null_mut()
                } else {
                    unsafe { $cxx_getter(self.0) }
                }
            }
        }

        unsafe impl crate::utils::AsNative<$T> for $wrapper {
            fn as_native(&self) -> *const $T {
                self.0.as_native()
            }

            fn as_native_mut(&mut self) -> *mut $T {
                self.0.as_native_mut()
            }
        }

        $(wrap_sp! { @accessor $wrapper(Sp<$T>) { $accessor_name: $accessor } })*
    };

    {@accessor $wrapper:ident(Sp<$T:ty>) { clone: $cxx_clone:path }} => {
        impl Clone for $wrapper {
            fn clone(&self) -> $wrapper {
                unsafe { $wrapper::from_raw($cxx_clone(self.0.as_native())).unwrap() }
            }
        }
    };

    {@accessor $wrapper:ident(Sp<$T:ty>) { destructor: $cxx_destructor:path }} => {
        impl Drop for $wrapper {
            fn drop(&mut self) {
                unsafe { $cxx_destructor(self.0.as_native_mut()) }
            }
        }
    };

    {@accessor $wrapper:ident(Sp<$T:ty>) { strong_count: $cxx_strong_count:path }} => {
        impl $wrapper {
            pub fn strong_count(&self) -> i32 {
                unsafe {
                    $cxx_strong_count(self.0.as_native())
                }
            }
        }
    };
}

/// Wrapper around the android weak reference-counted pointer.
///
/// Note: because this wrapper is generic, we cannot implement Drop that
/// decrements the ref count, because we would need to specialize on T in order
/// to call the right C++ function depending on the generic type. It is up to
/// users of `Sp` to properly decrement the pointer on drop if necessary.
#[repr(transparent)]
pub(crate) struct Wp<T>(pub(super) *mut android_wp<T>);

unsafe impl<T> AsNative<android_wp<T>> for Wp<T> {
    fn as_native(&self) -> *const android_wp<T> {
        self.0
    }

    fn as_native_mut(&mut self) -> *mut android_wp<T> {
        self.0
    }
}

impl<T> PartialEq for Wp<T>
where
    Wp<T>: AsNative<T>,
{
    fn eq(&self, other: &Self) -> bool {
        ptr::eq::<T>(self.as_native(), other.as_native())
    }
}

macro_rules! wrap_wp {
    {
        $(#[$attr:meta])*
        $vis:vis struct $wrapper:ident $(<$generic:ident: $obj_ty:ident>)? (Wp<$cxx_ty:ty>) {
            clone: $cxx_clone:path,
            destructor: $cxx_destructor:path,
            promote: ($sp:ty, $cxx_promote:path),
        }
    } => {
        // NOTE: The rust_object field should never be dereferenced. It only exists for promotion to an Sp.
        $(#[$attr])*
        $vis struct $wrapper<$($generic: $obj_ty)?> {
            wp: crate::utils::Wp<$cxx_ty>,
            $(rust_object: *mut $generic,)?
        }

        impl<$($generic: $obj_ty)?> $wrapper<$($generic)?> {
            pub(crate) unsafe fn from_raw(ptr: *mut android_wp<$cxx_ty> $(, rust_object: *mut $generic)?) -> Option<Self> {
                if ptr.is_null() {
                    return None;
                }

                let wp = Wp(ptr);

                // We always need to construct the wrapper before we return so that its
                // destructor is called.
                Some(Self { wp $(, rust_object: rust_object as *mut $generic)? })
                // wrapper is dropped here, triggering its destructor if any
            }

            pub fn promote(&self) -> $crate::error::Result<$sp> {
                let sp = unsafe { $cxx_promote(self.wp.as_native()) };

                if sp.is_null() {
                    return Err($crate::error::Error::DEAD_OBJECT);
                }

                unsafe {
                    <$sp>::from_raw(sp $(, self.rust_object as *mut $generic)?).ok_or(Error::DEAD_OBJECT)
                }
            }
        }

        unsafe impl<$($generic: $obj_ty)?> AsNative<android_wp<$cxx_ty>> for $wrapper<$($generic)?> {
            fn as_native(&self) -> *const android_wp<$cxx_ty> {
                self.wp.0
            }

            fn as_native_mut(&mut self) -> *mut android_wp<$cxx_ty> {
                self.wp.0
            }
        }

        impl<$($generic: $obj_ty)?> Clone for $wrapper<$($generic)?> {
            fn clone(&self) -> $wrapper<$($generic)?> {
                unsafe {
                    $wrapper::from_raw($cxx_clone(self.wp.as_native()) $(, self.rust_object as *mut $generic)?).unwrap()
                }
            }
        }

        impl<$($generic: $obj_ty)?> Drop for $wrapper<$($generic)?> {
            fn drop(&mut self) {
                unsafe { $cxx_destructor(self.wp.as_native_mut()) }
            }
        }
    };
}

/// Owned version of C++ `String8`, a UTF-8 string.
#[repr(transparent)]
pub struct String8(*mut android_String8);

impl String8 {
    pub fn new() -> Self {
        unsafe { Self(android_c_interface_NewString8()) }
    }

    pub unsafe fn from_raw(ptr: *mut android_String8) -> Self {
        Self(ptr)
    }

    pub fn append(&mut self, other: &Str8) -> Result<()> {
        binder_status(unsafe { android_String8_append(self.0, other.as_native()) })
    }

    pub fn append_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let status = unsafe {
            android_String8_append2(
                self.0,
                bytes.as_ptr() as *const libc::c_char,
                bytes.len().try_into().unwrap(),
            )
        };
        binder_status(status)
    }
}

impl Drop for String8 {
    fn drop(&mut self) {
        unsafe {
            android_c_interface_String8_Destroy(self.0);
        }
    }
}

unsafe impl AsNative<android_String8> for String8 {
    fn as_native(&self) -> *const android_String8 {
        self.0
    }

    fn as_native_mut(&mut self) -> *mut android_String8 {
        self.0
    }
}

impl From<&str> for String8 {
    fn from(s: &str) -> String8 {
        unsafe {
            String8(android_c_interface_NewString8FromUtf8(
                s.as_bytes().as_ptr().cast(),
                s.len().try_into().unwrap(),
            ))
        }
    }
}

impl From<&[u8]> for String8 {
    fn from(slice: &[u8]) -> Self {
        unsafe {
            String8(android_c_interface_NewString8FromUtf8(
                slice.as_ptr() as *const _,
                slice.len().try_into().unwrap(),
            ))
        }
    }
}

impl fmt::Debug for String8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl PartialEq for String8 {
    fn eq(&self, other: &String8) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl ops::Deref for String8 {
    type Target = Str8;

    #[inline]
    fn deref(&self) -> &Str8 {
        unsafe { Str8::from_ptr(self.0.cast()) }
    }
}

impl AsRef<Str8> for String8 {
    fn as_ref(&self) -> &Str8 {
        &*self
    }
}

/// Representation of a borrowed C++ `String8`, a UTF-8 string.
#[repr(transparent)]
pub struct Str8(android_String8);

impl Str8 {
    pub(crate) unsafe fn from_ptr<'a>(ptr: *const android_String8) -> &'a Str8 {
        &*ptr.cast()
    }

    // Should be safe to unwrap as String8 should also be a utf8 buffer
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_slice()).unwrap()
    }

    pub fn as_slice(&self) -> &[u8] {
        let mut data = unsafe { android_c_interface_String8_data(&self.0) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = ptr::NonNull::dangling().as_ptr();
        }

        unsafe { std::slice::from_raw_parts(data.cast(), self.len().try_into().unwrap()) }
    }

    pub fn len(&self) -> size_t {
        unsafe { android_String8_length(&self.0) }
    }

    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }
}

unsafe impl AsNative<android_String8> for Str8 {
    fn as_native(&self) -> *const android_String8 {
        &self.0
    }

    fn as_native_mut(&mut self) -> *mut android_String8 {
        &mut self.0
    }
}

impl fmt::Debug for Str8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl PartialEq for Str8 {
    fn eq(&self, other: &Str8) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<&str> for Str8 {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl ops::Deref for Str8 {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

/// Owned version of C++ `String16`, a UTF-16 string.
#[repr(transparent)]
pub struct String16(*mut android_String16);

impl String16 {
    pub fn new() -> Self {
        unsafe { Self(android_c_interface_NewString16()) }
    }

    pub unsafe fn from_raw(ptr: *mut android_String16) -> Self {
        Self(ptr)
    }

    pub fn append(&mut self, other: &Str16) -> Result<()> {
        binder_status(unsafe { android_String16_append(self.0, other.as_native()) })
    }
}

impl Drop for String16 {
    fn drop(&mut self) {
        unsafe {
            android_c_interface_String16_Destroy(self.0);
        }
    }
}

unsafe impl AsNative<android_String16> for String16 {
    fn as_native(&self) -> *const android_String16 {
        self.0
    }

    fn as_native_mut(&mut self) -> *mut android_String16 {
        self.0
    }
}

impl From<&str> for String16 {
    fn from(s: &str) -> String16 {
        let s: Vec<u16> = s.encode_utf16().collect();
        unsafe {
            String16(android_c_interface_NewString16FromUtf16(
                s.as_ptr(),
                s.len().try_into().unwrap(),
            ))
        }
    }
}

impl From<&[u8]> for String16 {
    fn from(slice: &[u8]) -> Self {
        unsafe {
            String16(android_c_interface_NewString16FromUtf8(
                slice.as_ptr() as *const _,
                slice.len().try_into().unwrap(),
            ))
        }
    }
}

impl fmt::Debug for String16 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl PartialEq for String16 {
    fn eq(&self, other: &String16) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl ops::Deref for String16 {
    type Target = Str16;

    #[inline]
    fn deref(&self) -> &Str16 {
        unsafe { Str16::from_ptr(self.0.cast()) }
    }
}

impl AsRef<Str16> for String16 {
    fn as_ref(&self) -> &Str16 {
        &*self
    }
}

/// Representation of a borrowed C++ `String16`, a UTF-16 string.
#[repr(transparent)]
pub struct Str16(android_String16);

impl Str16 {
    pub(crate) unsafe fn from_ptr<'a>(ptr: *const android_String16) -> &'a Str16 {
        &*ptr.cast()
    }

    pub(crate) fn to_owned(&self) -> String16 {
        unsafe { String16::from_raw(android_c_interface_CopyString16(self.as_native())) }
    }

    pub fn size(&self) -> size_t {
        unsafe { android_String16_size(self.as_native()) }
    }

    pub fn as_slice(&self) -> &[u16] {
        let mut data = unsafe { android_c_interface_String16_data(self.as_native()) };

        // Rust docs explicitly state data cannot be null, but can be dangling for 0
        // length slices
        if data.is_null() {
            data = ptr::NonNull::dangling().as_ptr();
        }

        unsafe { std::slice::from_raw_parts(data, self.size().try_into().unwrap()) }
    }

    pub fn to_string(&self) -> String {
        let slice = self.as_slice();
        std::char::decode_utf16(slice.into_iter().copied())
            .map(|r| r.unwrap_or(std::char::REPLACEMENT_CHARACTER))
            .collect()
    }
}

unsafe impl AsNative<android_String16> for Str16 {
    fn as_native(&self) -> *const android_String16 {
        &self.0 as *const _
    }

    fn as_native_mut(&mut self) -> *mut android_String16 {
        &mut self.0 as *mut _
    }
}

impl PartialEq for Str16 {
    fn eq(&self, other: &Str16) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl fmt::Debug for Str16 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl<T> fmt::Debug for android_sp<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format!("sp<{:?}>", type_name::<T>()).fmt(f)
    }
}

/// An Android unique file descriptor.
#[repr(transparent)]
pub struct UniqueFd(pub(crate) *mut android_base_unique_fd);

impl UniqueFd {
    pub fn new() -> Self {
        unsafe { UniqueFd(android_c_interface_NewUniqueFd()) }
    }

    pub unsafe fn reset(&mut self, fd: Option<RawFd>) {
        android_c_interface_UniqueFd_reset(self.0, fd.unwrap_or(-1))
    }
}

impl AsRawFd for UniqueFd {
    fn as_raw_fd(&self) -> RawFd {
        if self.0.is_null() {
            -1
        } else {
            unsafe { (*self.0).fd_ }
        }
    }
}

impl fmt::Debug for UniqueFd {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("UniqueFd").field(&self.as_raw_fd()).finish()
    }
}

impl Drop for UniqueFd {
    fn drop(&mut self) {
        unsafe { android_c_interface_UniqueFd_destructor(self.0) }
    }
}
