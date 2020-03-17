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
        reply: Option<&mut Parcel>,
        _flags: TransactionFlags,
    ) -> binder::Result<()> {
        reply.unwrap().write_utf8_as_utf16(TestService::test())?;
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
