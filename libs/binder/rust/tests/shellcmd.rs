use binder::interfaces::{BpResultReceiver, IResultReceiver};
use binder::parcel::Parcel;
use binder::service_manager::{DumpFlags, ServiceManager};
use binder::{
    Binder, Handle, IBinder, Interface, ProcessState, Result, Service, ThreadState,
    TransactionCode, TransactionFlags,
};

use std::io::Write;

#[allow(unused)]
pub const SERVICE_LOCAL: &'static str = "BinderRsTestServiceLocal";
#[allow(unused)]
pub const SERVICE_REMOTE: &'static str = "BinderRsTestServiceRemote";

struct TestService;

impl Binder for TestService {
    const INTERFACE_DESCRIPTOR: &'static str = "";

    fn on_transact(
        &self,
        code: TransactionCode,
        data: &Parcel,
        _reply: Option<&mut Parcel>,
        _flags: TransactionFlags,
    ) -> binder::Result<()> {
        match code {
            Interface::SHELL_COMMAND_TRANSACTION => {
                let _input = data.read_file()?;
                let mut output = data.read_file()?;
                let _err = data.read_file()?;
                let argc = data.read_i32()?;

                for _ in 0..argc {
                    write!(output, "{}", data.read_string16()?.to_string())
                        .expect("Could not write to output file in TestService");
                }

                let _ = data.read::<Interface>()?;
                let receiver = data.read::<Interface>()?;

                if !receiver.is_null() {
                    BpResultReceiver::new(receiver)?
                        .send(0)
                        .expect("Could not write to output file in TestService");
                }

                Ok(())
            }
            _ => panic!("Unexpected transaction"),
        }
    }
}

pub fn start_service(name: &'static str) -> Result<()> {
    ProcessState::start_thread_pool();
    let mut sm = ServiceManager::default();
    sm.add_service(
        name,
        Service::new(TestService).into(),
        false,
        DumpFlags::PriorityDefault,
    )
}

#[allow(unused)]
fn main() {
    assert!(start_service(SERVICE_REMOTE).is_ok());
    ProcessState::give_thread_pool_name();
    ThreadState::join_thread_pool(true);
}
