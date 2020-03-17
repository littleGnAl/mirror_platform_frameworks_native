#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

use super::libbinder_bindings::*;
use super::String16;
use crate::error::{binder_status, BinderResult};
use std::os::raw::c_void;

use std::convert::TryInto;
use std::fmt;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::ptr;

#[repr(C)]
pub(crate) struct Method {
    _private: [u8; 0],
}
#[repr(C)]
pub(crate) struct RTTI {
    _private: [u8; 0],
}

/// A Rust struct that inherits from a dynamic C++ class (i.e. a class which has
/// a vtable pointer).
///
/// # Safety
///
/// This trait must only be implemented for structs where the field at offset 0
/// is actually a C++ vtable pointer with a structure identical to the provided
/// `VTable` type. `VPTR_INDEX` must be the index of the vtable address point in
/// that vtable.
pub unsafe trait Class {
    type VTable;
    /// Index of the virtual pointer address (start of virtual function
    /// addresses) in the vtable for this class.
    ///
    /// For example, for the following virtual table layout, the index should be
    /// 3, since the vtable address points to the third entry in the table:
    ///   Vtable for 'android::IBinder' (32 entries).
    ///   0 | vbase_offset (8)
    ///   1 | offset_to_top (0)
    ///   2 | android::IBinder RTTI
    ///       -- (android::IBinder, 0) vtable address --
    ///   3 | sp<android::IInterface> android::IBinder::queryLocalInterface(const android::String16 &)
    const VPTR_INDEX: isize;

    /// Returns a pointer to the vtable for this class
    fn vtable(&self) -> &Self::VTable {
        unsafe {
            let vtable_at_address_point = *(self as *const _ as *const usize);
            &*(vtable_at_address_point as *const u8)
                .offset(-Self::VPTR_INDEX * (mem::size_of::<*const u8>() as isize))
                .cast()
        }
    }
}

/// A Rust struct that inherits from a C++ class with a virtual base class.
///
/// `Base` should be a Rust struct structurally identical to the virtual base
/// class.
///
/// # Safety
///
/// This trait can only be implemented for structs "inheriting" from a C++ class
/// that has virtual base `Base`. The struct must have an offset into itself
/// that is layout-compatible with `Base`.
pub unsafe trait VirtualBase<Base>: Class {
    /// Cast a C++ object to its virtual base class.
    fn as_virtual_base<'a>(&'a mut self) -> &'a mut Base;
}

/// Declare that the `class` struct is a C++ class that inherits from a single
/// C++ virtual base class `base`. `class` has vtable type `vtable` with vtable
/// address point at index `idx` into the vtable. The `vtable` struct must have
/// an `isize` field `_vbase_offset` that will hold the virtual base offset.
///
/// # Examples
///
/// Given the following C++ inheritance hierarchy:
///
/// ```c++
/// class DerivedClass : public virtual BaseClass { }
/// ```
///
/// And a `DerivedClass` vtable that starts with:
/// ```
///    0 | vbase_offset (8)
///    1 | offset_to_top (0)
///    2 | DerivedClass RTTI
///        -- (DerivedClass, 0) vtable address --
///    3 | DerivedClass::firstMethod()
/// ```
///
/// `idx` should be 3, since the vtable address point is at index 3 in the
/// vtable. Thus, the equivalant declarations in Rust are:
///
/// ```rust
/// struct BaseClass;
///
/// struct DerivedClass;
///
/// struct DerivedClassVTable {
///     _vbase_offset: isize,
///     _offset_to_top: isize,
///     _rtti: *const RTTI,
///     vtable: DerivedClassVFns,
///     ...
///     _base_vtable: BaseClassVTable,
/// }
///
/// inherit_virtual!(DerivedClass : BaseClass [DerivedClassVTable @ 3]);
/// ```
macro_rules! inherit_virtual {
    ($class:path : $base:path [$vtable:ident @ $idx:expr]) => {
        unsafe impl crate::native::utils::Class for $class {
            type VTable = $vtable;
            const VPTR_INDEX: isize = $idx;
        }

        unsafe impl crate::native::utils::VirtualBase<$base> for $class {
            fn as_virtual_base(&mut self) -> &mut $base {
                // The vbase offset field of the vtable gives the pointer offset
                // which must be applied to an object to cast it to an instance
                // of its virtual base. We look up this offset in the vtable,
                // apply it to `self`, and cast this address to a mutable
                // reference to our base. The referenced returned has the same
                // lifetime as `&mut self`, which is exactly what we need.
                unsafe {
                    &mut *(self as *mut _ as *mut u8)
                        .offset(crate::native::utils::Class::vtable(self)._vbase_offset)
                        .cast()
                }
            }
        }
    };
}

pub use super::libbinder_bindings::android_RefBase as RefBase;

/// C++ vtable for `android::RefBase`
#[repr(C)]
#[derive(Debug)]
pub(crate) struct RefBaseVTable {
    pub(crate) _offset_to_top: isize,
    pub(crate) _rtti: *const RTTI,
    pub(crate) vfns: RefBaseVFns,
}

/// Virtual functions of the `android::RefBase` vtable. This is the vtable
/// contents starting at at vtable address point.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct RefBaseVFns {
    pub(crate) _complete_destructor: *const Method,
    pub(crate) _deleting_destructor: *const Method,
    pub(crate) onFirstRef: *const Method,
    pub(crate) onLastStrongRef: *const Method,
    pub(crate) onIncStrongAttempted: *const Method,
    pub(crate) onLastWeakRef: *const Method,
}

pub(crate) type RefBaseVTablePtr = *const RefBaseVFns;

impl From<&str> for String16 {
    fn from(s: &str) -> String16 {
        let s: Vec<u16> = s.encode_utf16().collect();
        unsafe { String16::new5(s.as_ptr(), s.len() as u64) }
    }
}

#[cfg(target_pointer_width = "64")]
extern "C" {
    /// C++ new operator.
    #[link_name = "\u{1}_Znwm"]
    fn cxx_operator_new(size: usize) -> *mut c_void;
}

#[cfg(target_pointer_width = "32")]
extern "C" {
    /// C++ new operator.
    #[link_name = "\u{1}_Znwj"]
    fn cxx_operator_new(size: usize) -> *mut c_void;
}

/// C++ Class `android::sp`. A ref-counted strong pointer holding a object that
/// inherits from `android::RefBase`.
///
/// Technically `sp` isn't restricted to `android::RefBase` but is templated
/// over anything with the same API, but libbinder only deals with
/// `android::RefBase` pointees.
#[repr(transparent)]
pub struct Sp<T: VirtualBase<RefBase>>(android_sp<T>);

impl<T: VirtualBase<RefBase>> Sp<T> {
    /// Construct a new strong pointer.
    ///
    /// Increments the ref-count after running the `constructor`
    /// callback. Returns a `MaybeUninit` because we can't guarantee that
    /// `constructor` fully initializes the uninitialized object.
    pub(crate) fn new<F>(constructor: F) -> MaybeUninit<Sp<T>>
    where
        F: Fn(*mut T),
    {
        let mut this = Sp(android_sp {
            m_ptr: unsafe { cxx_operator_new(mem::size_of::<T>()) as *mut T },
            _phantom_0: PhantomData,
        });

        if (!this.is_null()) {
            constructor(this.0.m_ptr);

            let ref_base = this.as_virtual_base();
            unsafe {
                android_RefBase_incStrong(ref_base as *const _, ptr::null());
            }
        }

        MaybeUninit::new(this)
    }

    /// Construct a null strong pointer. Does not increment any ref-counts.
    pub(crate) fn null() -> Self {
        Self(android_sp {
            m_ptr: ptr::null_mut(),
            _phantom_0: PhantomData,
        })
    }

    /// Wraps an existing `android::sp` in a transparent Rust `Sp`.
    ///
    /// Does not increment the ref-count of this pointer.
    pub(crate) fn wrap(native_sp: android_sp<T>) -> Self {
        Self(native_sp)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.m_ptr.is_null()
    }

    pub(crate) unsafe fn as_mut_ptr(&mut self) -> *mut T {
        self.0.m_ptr
    }
}

impl<T: VirtualBase<RefBase>> Drop for Sp<T> {
    fn drop(&mut self) {
        if (!self.is_null()) {
            let id = self as *const _ as *const c_void;
            let ref_base = self.as_virtual_base();

            // We are guaranteed that ref_base is in fact a `android_RefBase` by
            // the invariant on `VirtualBase`, so we know we're passing the
            // right object.
            //
            // The id here is another matter... this id should be the address of
            // the `Sp` object itself. We can't guarantee that this id is
            // correct, because the `Sp` may have moved and we don't have a move
            // constructor in Rust to catch that. However, in practice it
            // doesn't matter that we may be lying about the id here. The id is
            // only used for debugging, and is ignored if `DEBUG_REFS=0` (see
            // RefBase.cpp).
            unsafe {
                android_RefBase_decStrong(ref_base as *const _, id);
            }
        }
    }
}

impl<T: VirtualBase<RefBase>> Deref for Sp<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // TODO: do we want to do a null check here?
        unsafe { self.0.m_ptr.as_ref().unwrap() }
    }
}

impl<T: VirtualBase<RefBase>> DerefMut for Sp<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // TODO: do we want to do a null check here?
        unsafe { self.0.m_ptr.as_mut().unwrap() }
    }
}

/// C++ class `android::String8`, a UTF-8 string.
pub struct String8(pub(crate) android_String8);

// A few extra impls for android::String8
impl String8 {
    pub fn new() -> Self {
        unsafe { String8(android_String8::new()) }
    }

    pub fn append(&mut self, str8: &String8) -> BinderResult<()> {
        let status = unsafe { android_String8_append(&mut self.0, &str8.0) };

        binder_status(status)
    }

    pub fn append_bytes(&mut self, bytes: &[u8]) -> BinderResult<()> {
        let status = unsafe {
            android_String8_append2(
                &mut self.0,
                bytes.as_ptr() as *const libc::c_char,
                bytes.len().try_into().unwrap(),
            )
        };

        binder_status(status)
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.0.mString as *const libc::c_uchar,
                self.0.length().try_into().unwrap(),
            )
        }
    }

    pub fn len(&self) -> size_t {
        unsafe { self.0.length() }
    }

    pub unsafe fn to_string(&self) -> String {
        std::str::from_utf8(self.as_slice()).unwrap().to_string()
    }

    // TODO: More methods?
}

impl fmt::Debug for String8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe { self.to_string() }.fmt(f)
    }
}

impl PartialEq for String8 {
    fn eq(&self, other: &String8) -> bool {
        self.as_slice() == other.as_slice()
    }
}

// A few extra impls for android::String16
impl String16 {
    pub unsafe fn as_slice(&self) -> &[u16] {
        std::slice::from_raw_parts(self.mString, self.size() as usize)
    }

    pub unsafe fn to_string(&self) -> String {
        let slice = self.as_slice();
        std::char::decode_utf16(slice.into_iter().copied())
            .map(|r| r.unwrap_or(std::char::REPLACEMENT_CHARACTER))
            .collect()
    }
}

impl fmt::Debug for String16 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe { self.to_string() }.fmt(f)
    }
}

impl PartialEq for String16 {
    fn eq(&self, other: &String16) -> bool {
        unsafe { self.as_slice() == other.as_slice() }
    }
}

impl fmt::Debug for android_IBinder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "IBinder".fmt(f)
    }
}

impl PartialEq for android_IBinder {
    fn eq(&self, other: &android_IBinder) -> bool {
        // FIXME: Not sure how to actually compare these, but needed an impl
        // for asserting result errors
        false
    }
}

impl<T> fmt::Debug for android_sp<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format!("sp<{:?}>", stringify!(T)).fmt(f)
    }
}

impl<T: PartialEq> PartialEq for android_sp<T> {
    fn eq(&self, other: &android_sp<T>) -> bool {
        unsafe { *self.m_ptr == *other.m_ptr }
    }
}
