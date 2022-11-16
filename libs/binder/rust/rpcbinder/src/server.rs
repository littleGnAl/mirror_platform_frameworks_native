/*
 * Copyright (C) 2022 The Android Open Source Project
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
    unstable_api::{AIBinder, AsNative},
    SpIBinder,
};
use binder_rpc_unstable_bindgen::RpcServerHandle;
use std::io::{Error, ErrorKind};
use std::sync::Mutex;
use std::{ffi::CString, os::raw, ptr::null_mut};

/// Foobar
pub struct RpcServer {
    handle: Mutex<RpcServerHandle>,
}

impl RpcServer {
    fn from_handle(handle: RpcServerHandle) -> Result<RpcServer, Error> {
        if handle == RpcServerHandle::MAX {
            return Err(Error::new(ErrorKind::Other, "Failed to start server"));
        }
        Ok(RpcServer { handle: Mutex::new(handle) })
    }

    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// vsock port.
    pub fn new_vsock(mut service: SpIBinder, port: u32) -> Result<RpcServer, Error> {
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        let handle = unsafe { binder_rpc_unstable_bindgen::VsockRpcServer(service, port) };
        Self::from_handle(handle)
    }

    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// socket file name. The socket should be initialized in init.rc with the same name.
    pub fn new_init_unix_domain(
        mut service: SpIBinder,
        socket_name: &str,
    ) -> Result<RpcServer, Error> {
        let socket_name = match CString::new(socket_name) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot convert {} to CString. Error: {:?}", socket_name, e);
                return Err(Error::from(ErrorKind::InvalidInput));
            }
        };
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        // RunInitUnixDomainRpcServer does not retain a reference to `ready_callback` or `param`;
        // it only uses them before it returns, which is during the lifetime of `self`.
        let handle = unsafe {
            binder_rpc_unstable_bindgen::InitUnixDomainRpcServer(service, socket_name.as_ptr())
        };
        Self::from_handle(handle)
    }

    /// Joins the RpcServer thread.
    pub fn join(&mut self) {
        let handle = self.handle.lock().unwrap();
        unsafe { binder_rpc_unstable_bindgen::JoinRpcServer(*handle) };
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        let handle = self.handle.lock().unwrap();
        unsafe { binder_rpc_unstable_bindgen::ShutdownRpcServer(*handle) };
    }
}

type RpcServerFactoryRef<'a> = &'a mut (dyn FnMut(u32) -> Option<SpIBinder> + Send + Sync);

/// Runs a binder RPC server, using the given factory function to construct a binder service
/// implementation for each connection.
///
/// The current thread is joined to the binder thread pool to handle incoming messages.
///
/// Returns true if the server has shutdown normally, false if it failed in some way.
pub fn run_vsock_rpc_server_with_factory(
    port: u32,
    mut factory: impl FnMut(u32) -> Option<SpIBinder> + Send + Sync,
) -> bool {
    // Double reference the factory because trait objects aren't FFI safe.
    // NB: The type annotation is necessary to ensure that we have a `dyn` rather than an `impl`.
    let mut factory_ref: RpcServerFactoryRef = &mut factory;
    let context = &mut factory_ref as *mut RpcServerFactoryRef as *mut raw::c_void;

    // SAFETY: `factory_wrapper` is only ever called by `RunVsockRpcServerWithFactory`, with context
    // taking the pointer value above (so a properly aligned non-null pointer to an initialized
    // `RpcServerFactoryRef`), within the lifetime of `factory_ref` (i.e. no more calls will be made
    // after `RunVsockRpcServerWithFactory` returns).
    unsafe {
        binder_rpc_unstable_bindgen::RunVsockRpcServerWithFactory(
            Some(factory_wrapper),
            context,
            port,
        )
    }
}

unsafe extern "C" fn factory_wrapper(cid: u32, context: *mut raw::c_void) -> *mut AIBinder {
    // SAFETY: `context` was created from an `&mut RpcServerFactoryRef` by
    // `run_vsock_rpc_server_with_factory`, and we are still within the lifetime of the value it is
    // pointing to.
    let factory_ptr = context as *mut RpcServerFactoryRef;
    let factory = factory_ptr.as_mut().unwrap();

    if let Some(mut service) = factory(cid) {
        service.as_native_mut()
    } else {
        null_mut()
    }
}
