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

use binder::declare_binder_interface;
use binder::parcel::Parcel;
use binder::{Binder, IBinder, Interface, ProcessState, SpIBinder, TransactionCode};

#[test]
fn servicemanager_connect() {
    let mut sm = binder::get_service("manager").expect("Did not get manager binder service");
    assert!(sm.is_binder_alive());
    assert!(sm.ping_binder().is_ok());
}

#[derive(Clone)]
struct TestService {
    s: String,
}

impl Interface for TestService {}

impl ITest for TestService {
    fn test(&self) -> binder::Result<String> {
        Ok("testing service".to_string())
    }
}

pub trait ITest: Interface {
    fn test(&self) -> binder::Result<String>;
}

declare_binder_interface! {
    ITest["android.os.ITest"] {
        native: BnTest(on_transact),
        proxy: BpTest {
            x: i32 = 100
        },
    }
}

fn on_transact(
    service: &dyn ITest,
    _code: TransactionCode,
    _data: &Parcel,
    reply: &mut Parcel,
) -> binder::Result<()> {
    reply.write(&service.test()?)?;
    Ok(())
}

impl ITest for BpTest {
    fn test(&self) -> binder::Result<String> {
        let reply = self
            .binder
            .transact(SpIBinder::FIRST_CALL_TRANSACTION, 0, |_| Ok(()))?;
        reply.read()
    }
}

impl ITest for Binder<BnTest> {
    fn test(&self) -> binder::Result<String> {
        self.0.test()
    }
}

#[test]
fn run_server() {
    ProcessState::start_thread_pool();
    let service = BnTest::new_binder(TestService { s: "".to_string() });
    let res = binder::add_service("testing", service.as_binder());
    assert!(res.is_ok());

    let test_client: Box<dyn ITest> =
        binder::get_interface("testing").expect("Did not get manager binder service");
    assert_eq!(test_client.test().unwrap(), "testing service");
}
