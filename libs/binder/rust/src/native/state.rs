use super::libbinder_bindings::*;

/// Start the Binder IPC thread pool
pub fn start_thread_pool() {
    unsafe { android_c_interface_StartThreadPool(); }
}

pub fn flush_commands() {
    unsafe { android_c_interface_FlushCommands(); }
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
        let _ = android_c_interface_GetThreadState();
    }
}

#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    link_section = ".init_array"
)]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [init_ipc_thread_state];
