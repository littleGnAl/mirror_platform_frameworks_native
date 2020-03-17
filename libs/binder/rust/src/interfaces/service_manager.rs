//! Manually implemented IServiceManager AIDL interface.

use crate::client::{BinderContainer, BinderInterface};
use crate::native::{self, Parcel, Status, String16};
use crate::service::{Binder, BinderService};
use crate::BinderResult;
use libc::c_int;

declare_binder_interface!(
    BpServiceManager,
    IServiceManager,
    "android.os.IServiceManager"
);

pub trait IServiceManager: BinderContainer {
    /// Retrieve an existing service called `name` from the service manager.
    ///
    /// This is the same as checkService (returns immediately) but exists for
    /// legacy purposes.
    ///
    /// Returns null if the service does not exist.
    fn get_service(&mut self, name: &str) -> BinderResult<BinderInterface>;

    /// Retrieve an existing service called `name` from the service
    /// manager. Non-blocking. Returns null if the service does not exist.
    fn check_service(&mut self, name: &str) -> BinderResult<BinderInterface>;

    /// Place a new service called `name` into the service manager.
    fn add_service<T: Binder>(
        &mut self,
        name: &str,
        service: &BinderService<T>,
        allow_isolated: bool,
        dumpsys_flags: i32,
    ) -> BinderResult<()>;

    /// Return a list of all currently running services.
    fn list_services(&mut self, dump_priority: i32) -> BinderResult<Vec<String16>>;

    /// Returns whether a given interface is declared on the device, even if it
    /// is not started yet. For instance, this could be a service declared in
    /// the VINTF manifest.
    fn is_declared(&mut self, name: &str) -> BinderResult<bool>;
}

#[allow(dead_code)]
impl BpServiceManager {
    const DUMP_FLAG_PRIORITY_CRITICAL: c_int = native::IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL;
    const DUMP_FLAG_PRIORITY_HIGH: c_int = native::IServiceManager::DUMP_FLAG_PRIORITY_HIGH;
    const DUMP_FLAG_PRIORITY_NORMAL: c_int = native::IServiceManager::DUMP_FLAG_PRIORITY_NORMAL;
    const DUMP_FLAG_PRIORITY_DEFAULT: c_int = native::IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT;
    const DUMP_FLAG_PRIORITY_ALL: c_int = native::IServiceManager::DUMP_FLAG_PRIORITY_ALL;
    const DUMP_FLAG_PROTO: c_int = native::IServiceManager::DUMP_FLAG_PROTO;
}

impl IServiceManager for BpServiceManager {
    fn get_service(&mut self, name: &str) -> BinderResult<BinderInterface> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&self.get_interface_descriptor().into())?;
        }
        data.write_utf8_as_utf16(name)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderInterface::FIRST_CALL_TRANSACTION + 0, // getService
            &data,
            &mut reply,
            0,
        )?;
        Status::from_parcel(&reply)?;
        reply.try_read::<BinderInterface>()
    }

    fn check_service(&mut self, name: &str) -> BinderResult<BinderInterface> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&self.get_interface_descriptor().into())?;
        }
        data.write_utf8_as_utf16(name)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderInterface::FIRST_CALL_TRANSACTION + 1, // checkService
            &data,
            &mut reply,
            0,
        )?;
        Status::from_parcel(&reply)?;
        reply.try_read::<BinderInterface>()
    }

    fn add_service<T: Binder>(
        &mut self,
        name: &str,
        service: &BinderService<T>,
        allow_isolated: bool,
        dump_priority: i32,
    ) -> BinderResult<()> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&self.get_interface_descriptor().into())?;
        }
        data.write_utf8_as_utf16(name)?;
        data.write_binder_native(service)?;
        data.write_bool(allow_isolated)?;
        data.write_i32(dump_priority)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderInterface::FIRST_CALL_TRANSACTION + 2, // addService
            &data,
            &mut reply,
            0,
        )?;
        let status = Status::from_parcel(&reply)?;
        status.into()
    }

    fn list_services(&mut self, dump_priority: i32) -> BinderResult<Vec<String16>> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&self.get_interface_descriptor().into())?;
        }
        data.write_i32(dump_priority)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderInterface::FIRST_CALL_TRANSACTION + 3, // listServices
            &data,
            &mut reply,
            0,
        )?;
        Status::from_parcel(&reply)?;

        unimplemented!("need to implement readUtf8VectorFromUtf16Vector");
        // reply.readUtf8VectorFromUtf16Vector()
    }

    fn is_declared(&mut self, name: &str) -> BinderResult<bool> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&self.get_interface_descriptor().into())?;
        }
        data.write_utf8_as_utf16(name)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderInterface::FIRST_CALL_TRANSACTION + 6, // isDeclared
            &data,
            &mut reply,
            0,
        )?;
        Status::from_parcel(&reply)?;
        reply.try_read_bool()
    }
}

#[test]
fn test_get_service() {
    let mut sm: BpServiceManager =
        crate::client::get_service("manager").expect("Did not get manager binder service");
    let mut sm = sm
        .get_service("manager")
        .expect("Did not get manager binder service via IServiceManager interface");
    assert_eq!(sm.get_interface_descriptor(), "android.os.IServiceManager");
}

#[test]
fn test_check_service() {
    let mut sm: BpServiceManager =
        crate::client::get_service("manager").expect("Did not get manager binder service");
    let mut sm = sm
        .check_service("manager")
        .expect("Did not get manager binder service via IServiceManager interface");
    assert_eq!(sm.get_interface_descriptor(), "android.os.IServiceManager");
}

#[test]
fn test_add_service() {
    use crate::service::{Binder, BinderNative};
    use crate::{TransactionCode, TransactionFlags};

    struct TestService;

    impl Binder for TestService {
        const INTERFACE_DESCRIPTOR: &'static str = "TestService";

        fn on_transact(
            &mut self,
            _code: TransactionCode,
            _data: &Parcel,
            reply: &mut Parcel,
            _flags: TransactionFlags,
        ) -> BinderResult<()> {
            reply.write_utf8_as_utf16("testing service")?;
            Ok(())
        }
    }

    let mut sm: BpServiceManager =
        crate::client::get_service("manager").expect("Did not get manager binder service");

    let binder_native = BinderNative::new(Box::new(TestService));
    assert!(sm.add_service("testing", &binder_native, false, 0).is_ok());
}

#[test]
fn test_is_declared() {
    let mut sm: BpServiceManager =
        crate::client::get_service("manager").expect("Did not get manager binder service");
    // TODO: Figure out how to test a true result from is_declared. AFAICT this
    // requires a VINTF interface?
    assert_eq!(sm.is_declared("bogus_service"), Ok(false));
}
