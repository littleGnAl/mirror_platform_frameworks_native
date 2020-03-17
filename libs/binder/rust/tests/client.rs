use binder::client::BinderInterface;
use binder::interfaces::BpServiceManager;

#[test]
fn servicemanager_get_interface() {
    let sm: BpServiceManager =
        binder::get_service("manager").expect("Did not get manager binder service");
    assert_eq!(sm.get_interface_descriptor(), "android.os.IServiceManager");
}
