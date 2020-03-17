use crate::parcel::Parcel;
use crate::service_manager::defaultServiceManager;
use crate::Interface;
use crate::String16;

#[test]
fn connect_to_servicemanager() {
    unsafe {
        let service_manager = defaultServiceManager().unwrap();

        service_manager.getInterfaceDescriptor();
    }
}

#[test]
fn raw_transact_interface() {
    unsafe {
        let service_manager = defaultServiceManager().unwrap();

        let mut sm = service_manager
            .getService(&String16::from("manager"))
            .unwrap();

        let input = Parcel::new();
        let mut output = Parcel::new();
        let status = sm.transact(
            Interface::INTERFACE_TRANSACTION,
            &input,
            Some(&mut output),
            0,
        );
        assert!(status.is_ok());
        let interface = output.read_string16();
        assert_eq!(interface.to_string(), "android.os.IServiceManager");
        assert_eq!(interface.as_ref(), service_manager.getInterfaceDescriptor());
    }
}
