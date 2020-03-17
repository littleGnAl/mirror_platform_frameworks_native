use crate::error::{binder_status, Result};
use crate::sys::libbinder_bindings::*;

use std::os::unix::io::RawFd;

/// Static utility functions to manage Binder process state.
pub struct ProcessState;

impl ProcessState {
    /// Start the Binder IPC thread pool
    pub fn start_thread_pool() {
        unsafe {
            android_c_interface_StartThreadPool();
        }
    }

    pub fn give_thread_pool_name() {
        unsafe {
            android_c_interface_GiveThreadPoolName();
        }
    }
}

/// Static utility functions to manage Binder thread state.
// TODO: Determine safety of associated functions
pub struct ThreadState;

impl ThreadState {
    /// Block on the Binder IPC thread pool
    pub fn join_thread_pool(is_main: bool) {
        unsafe {
            let ipc_thread_state = android_IPCThreadState_self();
            android_IPCThreadState_joinThreadPool(ipc_thread_state, is_main);
        }
    }

    pub fn get_calling_uid() -> libc::uid_t {
        unsafe {
            let ipc_thread_state = android_IPCThreadState_self();
            android_IPCThreadState_getCallingUid(ipc_thread_state)
        }
    }

    pub unsafe fn setup_polling() -> RawFd {
        let mut fd = 0;

        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_setupPolling(ipc_thread_state, &mut fd);

        fd
    }

    pub unsafe fn set_calling_work_source_uid(uid: libc::uid_t) -> i64 {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_setCallingWorkSourceUid(ipc_thread_state, uid)
    }

    pub unsafe fn get_calling_work_source_uid() -> libc::uid_t {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_getCallingWorkSourceUid(ipc_thread_state)
    }

    pub unsafe fn clear_calling_work_source() -> i64 {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_clearCallingWorkSource(ipc_thread_state)
    }

    pub unsafe fn clear_propagate_work_source() {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_clearPropagateWorkSource(ipc_thread_state)
    }

    pub unsafe fn should_propagate_work_source() -> bool {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_shouldPropagateWorkSource(ipc_thread_state)
    }

    pub unsafe fn restore_calling_work_source(token: i64) {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_restoreCallingWorkSource(ipc_thread_state, token)
    }

    pub unsafe fn set_calling_work_source_uid_without_propagation(uid: libc::uid_t) -> i64 {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_setCallingWorkSourceUidWithoutPropagation(ipc_thread_state, uid)
    }

    pub unsafe fn handle_polled_commands() -> Result<()> {
        let ipc_thread_state = android_IPCThreadState_self();
        binder_status(android_IPCThreadState_handlePolledCommands(
            ipc_thread_state,
        ))
    }

    pub fn flush_commands() {
        unsafe {
            let ipc_thread_state = android_IPCThreadState_self();
            android_IPCThreadState_flushCommands(ipc_thread_state);
        }
    }
}
