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

use crate::parcel::Parcel;
use crate::service_manager::{DumpFlags, ServiceManager};
use crate::{IBinder, Interface, String16};

#[test]
fn connect_to_servicemanager() {
    let mut service_manager = ServiceManager::default();
    let service_list = service_manager.list_services(DumpFlags::default());
    assert!(service_list.len() > 0);
}

#[test]
fn raw_transact_interface() {
    let service_manager = ServiceManager::default();

    let mut sm = service_manager.get_service("manager").unwrap();

    let input = Parcel::new();
    let mut output = Parcel::new();
    let status = sm.transact(
        Interface::INTERFACE_TRANSACTION,
        &input,
        Some(&mut output),
        0,
    );
    assert!(status.is_ok());
    let interface: String16 = output.read().unwrap();
    assert_eq!(interface.to_string(), "android.os.IServiceManager");
}
