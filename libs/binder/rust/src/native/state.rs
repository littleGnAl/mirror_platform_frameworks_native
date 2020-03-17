use super::libbinder_bindings::*;
use super::utils::{RefBase, RefBaseVTable, Sp};

extern "C" {
    #[link_name = "\u{1}_ZN7android12ProcessState4selfEv"]
    pub fn ProcessState_self(out: *mut android_sp<android_ProcessState>);
}

/// C++ vtable for `android::ProcessState`
pub struct ProcessStateVTable {
    _vbase_offset: isize,
    _base_vtable: RefBaseVTable,
}

inherit_virtual!(android_ProcessState : RefBase [ProcessStateVTable @ 3]);

/// Start the Binder IPC thread pool
pub fn start_thread_pool() {
    let mut process_state: Sp<android_ProcessState> = Sp::null();
    unsafe {
        ProcessState_self(&mut process_state as *mut _ as *mut _);
        android_ProcessState_startThreadPool(process_state.as_mut_ptr());
    }
}

pub fn flush_commands() {
    unsafe {
        let ipc_thread_state = android_IPCThreadState_self();
        android_IPCThreadState_flushCommands(ipc_thread_state);
    }
}

// Initialize an IPCThreadState from the main thread, before anyone spins up a
// child thread and initializes thread-local state in binder. Doing this on the
// main thread is necessary so that when libbinder C++ static destructors are
// called, binder has an IPCThreadState already on the main thread. Trying to
// initialize a new IPCThreadstate inside the static destructors was causing
// non-deterministic segfaults, presumably due to use-after-free of static
// globals. This was observed because the Rust test harness always executes
// tests on a child thread while the C++ global static destructors run on the
// main thread.
extern "C" fn init_ipc_thread_state() {
    unsafe {
        let _ = android_IPCThreadState_self();
    }
}

#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    link_section = ".init_array"
)]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [init_ipc_thread_state];
