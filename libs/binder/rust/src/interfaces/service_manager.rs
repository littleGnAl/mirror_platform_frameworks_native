//! Manually implemented IServiceManager AIDL interface.

use crate::client::{BinderClient, BinderInterface};
use crate::native::{self, Parcel, Sp, Status, String16};
use crate::service::{Binder, BinderService};
use crate::BinderResult;
use libc::c_int;

declare_binder_interface!(
    BpServiceManager,
    IServiceManager,
    "android.os.IServiceManager"
);

pub trait IServiceManager: BinderInterface {
    fn get_service(&mut self, name: &str) -> BinderResult<BinderClient>;

    fn check_service(&mut self, name: &str) -> BinderResult<BinderClient>;

    fn add_service<T: Binder>(
        &mut self,
        name: &str,
        service: &Sp<BinderService<T>>,
        allow_isolated: bool,
        dumpsys_flags: i32,
    ) -> BinderResult<()>;

    fn list_services(&mut self, dump_priority: i32) -> BinderResult<Vec<String16>>;

    fn wait_for_service(&mut self, name: &str) -> BinderResult<BinderClient>;

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
    fn list_services(&mut self, dump_priority: i32) -> BinderResult<Vec<String16>> {
        let mut data = Parcel::new();
        data.write_i32(dump_priority)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderClient::FIRST_CALL_TRANSACTION + 3, // listServices
            &data,
            &mut reply,
            0,
        )?;
        let _status = Status::from_parcel(&reply);

        unimplemented!("need to implement readUtf8VectorFromUtf16Vector");
        // reply.readUtf8VectorFromUtf16Vector()
    }

    fn get_service(&mut self, _name: &str) -> BinderResult<BinderClient> {
        unimplemented!("Need to implement more parcel interfaces for this");
    }

    fn check_service(&mut self, _name: &str) -> BinderResult<BinderClient> {
        unimplemented!("Need to implement more parcel interfaces for this");
    }

    fn add_service<T: Binder>(
        &mut self,
        name: &str,
        service: &Sp<BinderService<T>>,
        allow_isolated: bool,
        dump_priority: i32,
    ) -> BinderResult<()> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&self.get_interface_descriptor().into())?;
        }
        data.write_utf8_as_utf16(name)?;
        data.write_binder(service)?;
        data.write_bool(allow_isolated)?;
        data.write_i32(dump_priority)?;
        let mut reply = Parcel::new();
        self.0.transact(
            BinderClient::FIRST_CALL_TRANSACTION + 2, // addService
            &data,
            &mut reply,
            0,
        )?;
        let status = Status::from_parcel(&reply)?;
        status.into()
    }

    fn wait_for_service(&mut self, _name: &str) -> BinderResult<BinderClient> {
        unimplemented!("Need to implement more parcel interfaces for this");
    }

    fn is_declared(&mut self, _name: &str) -> BinderResult<bool> {
        let input = Parcel::new();
        // TODO: write interface token to input
        // TODO: write name to input
        let mut reply = Parcel::new();
        self.0
            .transact(
                BinderClient::FIRST_CALL_TRANSACTION + 6, // isDeclared
                &input,
                &mut reply,
                0,
            )
            .expect("getInterfaceDescriptor transaction failed");
        unimplemented!("Need to be able to read bool from parcel");
    }
}
