use crate::parcel::Parcel;
use crate::service_manager::{DumpFlags, ServiceManager};
use crate::{IBinder, Interface};

#[test]
fn connect_to_servicemanager() {
    let mut service_manager = ServiceManager::default();
    let service_list = service_manager.list_services(DumpFlags::default());
    assert!(service_list.len() > 0);
}

#[test]
fn raw_transact_interface() {
    let service_manager = ServiceManager::default();

    let mut sm = service_manager.get_service("manager").unwrap();

    let input = Parcel::new();
    let mut output = Parcel::new();
    let status = sm.transact(
        Interface::INTERFACE_TRANSACTION,
        &input,
        Some(&mut output),
        0,
    );
    assert!(status.is_ok());
    let interface = output.read_string16().unwrap();
    assert_eq!(interface.to_string(), "android.os.IServiceManager");
}
