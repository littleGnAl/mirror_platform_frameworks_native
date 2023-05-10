/*
 * Copyright (C) 2023 The Android Open Source Project
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
#![cfg(test)]

use binder::{IBinder, Strong};
use binderRpcTestIface::aidl::IBinderRpcTest::IBinderRpcTest;
use rpcbinder::RpcSession;
use tipc::Handle;
use trusty_std::ffi::{CString, FallibleCString};

test::init!();

const SERVICE_PORT: &str = "com.android.trusty.binderRpcTestService.V1";

fn get_service() -> Strong<dyn IBinderRpcTest> {
    RpcSession::new()
        .setup_preconnected_client(|| {
            let port = CString::try_new(SERVICE_PORT).expect("Failed to allocate port name");
            let h = Handle::connect(port.as_c_str())
                .expect("Failed to connect to service port {SERVICE_PORT}");

            // Do not close the handle at the end of the scope
            let fd = h.as_raw_fd();
            core::mem::forget(h);
            Some(fd)
        })
        .expect("Failed to create session")
}

#[test]
fn ping() {
    let srv = get_service();
    assert_eq!(srv.as_binder().ping_binder(), Ok(()));
}
