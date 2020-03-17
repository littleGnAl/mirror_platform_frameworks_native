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
use binder::interfaces::{BpServiceManager, IServiceManager};
use binder::parcel::Parcel;
use binder::service_manager::DumpFlags;
use binder::{Binder, IBinder, ProcessState, Service};
use binder::{TransactionCode, TransactionFlags};

#[test]
fn servicemanager_get_interface() {
    let sm: BpServiceManager =
        binder::get_service("manager").expect("Did not get manager binder service");
    assert_eq!(
        sm.get_interface_descriptor().to_string(),
        "android.os.IServiceManager"
    );
}

struct TestService;

impl TestService {
    fn test() -> &'static str {
        "testing service"
    }
}

impl Binder for TestService {
    const INTERFACE_DESCRIPTOR: &'static str = <Self as ITest>::INTERFACE_DESCRIPTOR;

    fn on_transact(
        &self,
        _code: TransactionCode,
        _data: &Parcel,
        reply: &mut Parcel,
        _flags: TransactionFlags,
    ) -> binder::Result<()> {
        reply.write_utf8_as_utf16(TestService::test())?;
        Ok(())
    }
}

impl ITest for TestService {
    fn test(&mut self) -> binder::Result<String> {
        Ok(TestService::test().to_string())
    }
}

pub trait ITest {
    const INTERFACE_DESCRIPTOR: &'static str = "android.os.ITest";

    fn test(&mut self) -> binder::Result<String>;
}

declare_binder_interface!(BpTest: ITest);

impl ITest for BpTest {
    fn test(&mut self) -> binder::Result<String> {
        let mut reply = Parcel::new();
        self.0.transact(
            binder::Interface::FIRST_CALL_TRANSACTION,
            &Parcel::new(),
            Some(&mut reply),
            0,
        )?;
        Ok(reply.read_string16().unwrap().to_string())
    }
}

#[test]
fn run_server() {
    ProcessState::start_thread_pool();
    let mut sm: BpServiceManager =
        binder::get_service("manager").expect("Did not get manager binder service");
    let binder_native = Service::new(TestService);
    let res = sm.add_service("testing", &binder_native, false, DumpFlags::PriorityDefault);
    assert!(res.is_ok());

    let mut test_client: BpTest =
        binder::get_service("testing").expect("Did not get manager binder service");
    assert_eq!(test_client.test(), Ok("testing service".to_string()));
}
