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

use binder::{unstable_api::new_spibinder, FromIBinder, SpIBinder, StatusCode, Strong};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use std::ffi::CString;
use std::os::{
    raw::{c_int, c_void},
    unix::io::RawFd,
};
use std::path::Path;

/// Connects to an RPC Binder server over vsock.
pub fn get_vsock_rpc_service(cid: u32, port: u32) -> Option<SpIBinder> {
    // SAFETY: AIBinder returned by VsockRpcClient has correct reference count,
    // and the ownership can safely be taken by new_spibinder.
    unsafe { new_spibinder(binder_rpc_unstable_bindgen::VsockRpcClient(cid, port)) }
}

/// Connects to an RPC Binder server for a particular interface over vsock.
pub fn get_vsock_rpc_interface<T: FromIBinder + ?Sized>(
    cid: u32,
    port: u32,
) -> Result<Strong<T>, StatusCode> {
    interface_cast(get_vsock_rpc_service(cid, port))
}

fn try_get_unix_domain_rpc_service<P: AsRef<Path>>(socket_path: P) -> Option<SpIBinder> {
    let socket_path = CString::new(socket_path.as_ref().to_str().expect("path to_str failed"))
        .expect("CString::new failed");
    // SAFETY: AIBinder returned by UnixDomainRpcClient has correct reference count,
    // and the ownership can safely be taken by new_spibinder.
    unsafe { new_spibinder(binder_rpc_unstable_bindgen::UnixDomainRpcClient(socket_path.as_ptr())) }
}

/// Connects to an RPC Binder server over Unix domain socket.
pub fn get_unix_domain_rpc_service<P: AsRef<Path>>(socket_path: P) -> Option<SpIBinder> {
    if socket_path.as_ref().exists() {
        return try_get_unix_domain_rpc_service(socket_path);
    }
    let instance = Inotify::init(InitFlags::empty()).unwrap();
    instance.add_watch(socket_path.as_ref(), AddWatchFlags::IN_ALL_EVENTS).unwrap();
    loop {
        let events = instance.read_events().unwrap();
        for event in events {
            if Some(socket_path.as_ref().as_os_str().to_os_string()) == event.name {
                log::debug!("socket_path Event: {:?}", event);
                return try_get_unix_domain_rpc_service(socket_path);
            }
        }
    }
}

/// Connects to an RPC Binder server for a particular interface over Unix domain socket.
pub fn get_unix_domain_rpc_interface<T: FromIBinder + ?Sized, P: AsRef<Path>>(
    socket_path: P,
) -> Result<Strong<T>, StatusCode> {
    interface_cast(get_unix_domain_rpc_service(socket_path))
}

/// Connects to an RPC Binder server, using the given callback to get (and take ownership of)
/// file descriptors already connected to it.
pub fn get_preconnected_rpc_service(
    mut request_fd: impl FnMut() -> Option<RawFd>,
) -> Option<SpIBinder> {
    // Double reference the factory because trait objects aren't FFI safe.
    let mut request_fd_ref: RequestFd = &mut request_fd;
    let param = &mut request_fd_ref as *mut RequestFd as *mut c_void;

    // SAFETY: AIBinder returned by RpcPreconnectedClient has correct reference count, and the
    // ownership can be safely taken by new_spibinder. RpcPreconnectedClient does not take ownership
    // of param, only passing it to request_fd_wrapper.
    unsafe {
        new_spibinder(binder_rpc_unstable_bindgen::RpcPreconnectedClient(
            Some(request_fd_wrapper),
            param,
        ))
    }
}

type RequestFd<'a> = &'a mut dyn FnMut() -> Option<RawFd>;

unsafe extern "C" fn request_fd_wrapper(param: *mut c_void) -> c_int {
    // SAFETY: This is only ever called by RpcPreconnectedClient, within the lifetime of the
    // BinderFdFactory reference, with param being a properly aligned non-null pointer to an
    // initialized instance.
    let request_fd_ptr = param as *mut RequestFd;
    let request_fd = request_fd_ptr.as_mut().unwrap();
    if let Some(fd) = request_fd() {
        fd
    } else {
        -1
    }
}

/// Connects to an RPC Binder server for a particular interface, using the given callback to get
/// (and take ownership of) file descriptors already connected to it.
pub fn get_preconnected_rpc_interface<T: FromIBinder + ?Sized>(
    request_fd: impl FnMut() -> Option<RawFd>,
) -> Result<Strong<T>, StatusCode> {
    interface_cast(get_preconnected_rpc_service(request_fd))
}

fn interface_cast<T: FromIBinder + ?Sized>(
    service: Option<SpIBinder>,
) -> Result<Strong<T>, StatusCode> {
    if let Some(service) = service {
        FromIBinder::try_from(service)
    } else {
        Err(StatusCode::NAME_NOT_FOUND)
    }
}
