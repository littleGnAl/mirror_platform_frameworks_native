use binder::{ProcessState, ThreadState};

mod shellcmd;

fn main() {
    assert!(shellcmd::start_service(shellcmd::SERVICE_REMOTE).is_ok());
    ProcessState::give_thread_pool_name();
    ThreadState::join_thread_pool(true);
}
