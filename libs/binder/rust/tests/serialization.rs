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

use binder::{
    declare_binder_interface, Binder, ExceptionCode, IBinder, Interface, Parcel, SpIBinder, Status,
    StatusCode, TransactionCode,
};

use std::error::Error;
use std::ffi::CString;

extern "C" {
    #[no_mangle]
    fn send_transaction() -> bool;
}

static I8S: &[i8; 4] = &[-128, 0, 117, 127];
static U8S: &[u8; 4] = &[0, 42, 117, 255];
static U16S: &[u16; 4] = &[0, 42, 117, u16::max_value()];
static I32S: &[i32; 4] = &[i32::min_value(), 0, 117, i32::max_value()];
static I64S: &[i64; 4] = &[i64::min_value(), 0, 117, i64::max_value()];
static U64S: &[u64; 4] = &[0, 42, 117, u64::max_value()];
static FLOATS: &[f32; 4] = &[f32::NAN, -f32::INFINITY, 117.0, f32::INFINITY];
static DOUBLES: &[f64; 4] = &[f64::NAN, -f64::INFINITY, 117.0, f64::INFINITY];
static BOOLS: &[bool; 4] = &[true, false, false, true];
static STRINGS: &[Option<&'static str>; 4] = &[Some(""), None, Some("test"), Some("😁")];

pub trait ReadParcelTest: Interface {}

declare_binder_interface! {
    ReadParcelTest["read_parcel_test"] {
        native: BnReadParcelTest(on_transact),
        proxy: BpReadParcelTest,
    }
}

impl ReadParcelTest for Binder<BnReadParcelTest> {}

impl ReadParcelTest for BpReadParcelTest {}

impl ReadParcelTest for () {}

#[allow(clippy::float_cmp)]
fn on_transact(
    _service: &dyn ReadParcelTest,
    code: TransactionCode,
    parcel: &Parcel,
    reply: &mut Parcel,
) -> binder::Result<()> {
    assert_eq!(code, SpIBinder::FIRST_CALL_TRANSACTION);

    assert_eq!(parcel.read::<bool>()?, true);
    assert_eq!(parcel.read::<bool>()?, false);
    assert_eq!(parcel.read::<Vec<bool>>()?, BOOLS);
    assert_eq!(parcel.read::<Option<Vec<bool>>>()?, None);

    assert_eq!(parcel.read::<i8>()?, 0);
    assert_eq!(parcel.read::<i8>()?, 1);
    assert_eq!(parcel.read::<i8>()?, i8::max_value());
    assert_eq!(parcel.read::<Vec<i8>>()?, I8S);
    assert_eq!(parcel.read::<Vec<u8>>()?, U8S);
    assert_eq!(parcel.read::<Option<Vec<i8>>>()?, None);

    assert_eq!(parcel.read::<u16>()?, 0);
    assert_eq!(parcel.read::<u16>()?, 1);
    assert_eq!(parcel.read::<u16>()?, u16::max_value());
    assert_eq!(parcel.read::<Vec<u16>>()?, U16S);
    assert_eq!(parcel.read::<Option<Vec<u16>>>()?, None);

    assert_eq!(parcel.read::<i32>()?, 0);
    assert_eq!(parcel.read::<i32>()?, 1);
    assert_eq!(parcel.read::<i32>()?, i32::max_value());
    assert_eq!(parcel.read::<Vec<i32>>()?, I32S);
    assert_eq!(parcel.read::<Option<Vec<i32>>>()?, None);

    assert_eq!(parcel.read::<i64>()?, 0);
    assert_eq!(parcel.read::<i64>()?, 1);
    assert_eq!(parcel.read::<i64>()?, i64::max_value());
    assert_eq!(parcel.read::<Vec<i64>>()?, I64S);
    assert_eq!(parcel.read::<Option<Vec<i64>>>()?, None);

    assert_eq!(parcel.read::<u64>()?, 0);
    assert_eq!(parcel.read::<u64>()?, 1);
    assert_eq!(parcel.read::<u64>()?, u64::max_value());
    assert_eq!(parcel.read::<Vec<u64>>()?, U64S);
    assert_eq!(parcel.read::<Option<Vec<u64>>>()?, None);

    assert_eq!(parcel.read::<f32>()?, 0f32);
    let floats = parcel.read::<Vec<f32>>()?;
    assert!(floats[0].is_nan());
    assert_eq!(floats[1..], FLOATS[1..]);
    assert_eq!(parcel.read::<Option<Vec<f32>>>()?, None);

    assert_eq!(parcel.read::<f64>()?, 0f64);
    let doubles = parcel.read::<Vec<f64>>()?;
    assert!(doubles[0].is_nan());
    assert_eq!(doubles[1..], DOUBLES[1..]);
    assert_eq!(parcel.read::<Option<Vec<f64>>>()?, None);

    let s: Option<String> = parcel.read()?;
    assert_eq!(s.as_deref(), Some("testing"));
    let s: Option<String> = parcel.read()?;
    assert_eq!(s, None);
    let s: Option<Vec<Option<String>>> = parcel.read()?;
    for (s, expected) in s.unwrap().iter().zip(STRINGS.iter()) {
        assert_eq!(s.as_deref(), *expected);
    }
    let s: Option<Vec<Option<String>>> = parcel.read()?;
    assert_eq!(s, None);

    let status: Status = parcel.read()?;
    assert!(status.is_ok());
    let status: Status = parcel.read()?;
    assert_eq!(status.exception_code(), ExceptionCode::NULL_POINTER);
    assert_eq!(
        status.get_description(),
        "Status(-4, EX_NULL_POINTER): 'a status message'"
    );
    let status: Status = parcel.read()?;
    assert_eq!(status.service_specific_error(), 42);
    assert_eq!(
        status.get_description(),
        "Status(-8, EX_SERVICE_SPECIFIC): '42: a service-specific error'"
    );

    assert!(parcel.read::<Option<SpIBinder>>()?.is_some());
    assert!(parcel.read::<Option<SpIBinder>>()?.is_none());
    let ibinders = parcel.read::<Option<Vec<Option<SpIBinder>>>>()?.unwrap();
    assert_eq!(ibinders.len(), 2);
    assert!(ibinders[0].is_some());
    assert!(ibinders[1].is_none());
    assert!(parcel.read::<Option<Vec<Option<SpIBinder>>>>()?.is_none());

    assert_eq!(parcel.read::<i32>(), Err(StatusCode::NOT_ENOUGH_DATA));

    reply.write(&true)?;
    reply.write(&false)?;
    reply.write(&BOOLS[..])?;
    reply.write(&(None as Option<Vec<bool>>))?;

    reply.write(&0i8)?;
    reply.write(&1i8)?;
    reply.write(&i8::max_value())?;
    reply.write(&I8S[..])?;
    reply.write(&U8S[..])?;
    reply.write(&(None as Option<Vec<i8>>))?;

    reply.write(&0u16)?;
    reply.write(&1u16)?;
    reply.write(&u16::max_value())?;
    reply.write(&U16S[..])?;
    reply.write(&(None as Option<Vec<u16>>))?;

    reply.write(&0i32)?;
    reply.write(&1i32)?;
    reply.write(&i32::max_value())?;
    reply.write(&I32S[..])?;
    reply.write(&(None as Option<Vec<i32>>))?;

    reply.write(&0i64)?;
    reply.write(&1i64)?;
    reply.write(&i64::max_value())?;
    reply.write(&I64S[..])?;
    reply.write(&(None as Option<Vec<i64>>))?;

    reply.write(&0u64)?;
    reply.write(&1u64)?;
    reply.write(&u64::max_value())?;
    reply.write(&U64S[..])?;
    reply.write(&(None as Option<Vec<u64>>))?;

    reply.write(&0f32)?;
    reply.write(&FLOATS[..])?;
    reply.write(&(None as Option<Vec<f32>>))?;

    reply.write(&0f64)?;
    reply.write(&DOUBLES[..])?;
    reply.write(&(None as Option<Vec<f64>>))?;

    reply.write("testing")?;
    reply.write(&(None as Option<String>))?;
    reply.write(&STRINGS[..])?;
    reply.write(&(None as Option<Vec<String>>))?;

    reply.write(&Status::ok())?;
    reply.write(&Status::new_exception(
        ExceptionCode::NULL_POINTER,
        Some(&CString::new("a status message").unwrap()),
    ))?;
    reply.write(&Status::new_service_specific_error(
        42,
        Some(&CString::new("a service-specific error").unwrap()),
    ))?;

    let service = binder::get_service("read_parcel_test");
    reply.write(&service.as_ref())?;
    reply.write(&(None as Option<&SpIBinder>))?;
    reply.write(&[service.as_ref(), None][..])?;
    reply.write(&(None as Option<Vec<Option<&SpIBinder>>>))?;

    Ok(())
}

#[test]
fn test_parcel_serialization() -> Result<(), Box<dyn Error>> {
    let service = BnReadParcelTest::new_binder(());

    binder::add_service("read_parcel_test", service.as_binder())?;

    unsafe {
        assert!(send_transaction());
    }

    Ok(())
}
