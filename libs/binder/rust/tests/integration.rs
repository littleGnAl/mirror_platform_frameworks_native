/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Rust Binder crate integration tests

use binder::declare_binder_interface;
use binder::parcel::Parcel;
use binder::{Binder, IBinder, Interface, SpIBinder, TransactionCode};

/// Name of service runner.
///
/// Must match the binary name in Android.bp
#[cfg(test)]
const RUST_SERVICE_BINARY: &str = "./rustBinderTestService";

/// Binary to run a test service.
///
/// This needs to be in a separate process from the tests, so we spawn this
/// binary as a child, providing the service name as an argument.
fn main() {
    binder::ProcessState::start_thread_pool();

    let service_name = std::env::args()
        .nth(1)
        .expect("Expected service name argument");
    {
        let service = BnTest::new_binder(TestService { s: "".to_string() });
        binder::add_service(&service_name, service.as_binder())
            .expect("Could not register service");
    }

    binder::ProcessState::join_thread_pool();
}

#[derive(Clone)]
struct TestService {
    s: String,
}

impl Interface for TestService {}

impl ITest for TestService {
    fn test(&self) -> binder::Result<String> {
        Ok("testing service".to_string())
    }
}

/// Trivial testing binder interface
pub trait ITest: Interface {
    /// Returns a test string
    fn test(&self) -> binder::Result<String>;
}

declare_binder_interface! {
    ITest["android.os.ITest"] {
        native: BnTest(on_transact),
        proxy: BpTest {
            x: i32 = 100
        },
    }
}

fn on_transact(
    service: &dyn ITest,
    _code: TransactionCode,
    _data: &Parcel,
    reply: &mut Parcel,
) -> binder::Result<()> {
    reply.write(&service.test()?)?;
    Ok(())
}

impl ITest for BpTest {
    fn test(&self) -> binder::Result<String> {
        let reply = self
            .binder
            .transact(SpIBinder::FIRST_CALL_TRANSACTION, 0, |_| Ok(()))?;
        reply.read()
    }
}

impl ITest for Binder<BnTest> {
    fn test(&self) -> binder::Result<String> {
        self.0.test()
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Child, Command};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use binder::{DeathRecipient, IBinder, SpIBinder};

    use super::{ITest, RUST_SERVICE_BINARY};

    pub struct ScopedServiceProcess(Child);

    impl ScopedServiceProcess {
        pub fn new(identifier: &str) -> Self {
            Self(
                Command::new(RUST_SERVICE_BINARY)
                    .arg(identifier)
                    .spawn()
                    .expect("Could not start service"),
            )
        }
    }

    impl Drop for ScopedServiceProcess {
        fn drop(&mut self) {
            self.0.kill().expect("Could not kill child process");
            self.0
                .wait()
                .expect("Could not wait for child process to die");
        }
    }

    #[test]
    fn servicemanager_connect() {
        let mut sm = binder::get_service("manager").expect("Did not get manager binder service");
        assert!(sm.is_binder_alive());
        assert!(sm.ping_binder().is_ok());
    }

    #[test]
    fn trivial_client() {
        let service_name = "trivial_client_test";
        let _process = ScopedServiceProcess::new(service_name);
        let test_client: Box<dyn ITest> =
            binder::get_interface(service_name).expect("Did not get manager binder service");
        assert_eq!(test_client.test().unwrap(), "testing service");
    }

    fn register_death_notification(binder: &mut SpIBinder) -> (Arc<AtomicBool>, DeathRecipient) {
        let binder_died = Arc::new(AtomicBool::new(false));

        let mut death_recipient = {
            let flag = binder_died.clone();
            DeathRecipient::new(move || {
                flag.store(true, Ordering::Relaxed);
            })
        };

        binder
            .link_to_death(&mut death_recipient)
            .expect("link_to_death failed");

        (binder_died, death_recipient)
    }

    /// Killing a remote service should unregister the service and trigger
    /// death notifications.
    #[test]
    fn test_death_notifications() {
        binder::ProcessState::start_thread_pool();

        let service_name = "test_death_notifications";
        let service_process = ScopedServiceProcess::new(service_name);
        let mut remote = binder::get_service(service_name).expect("Could not retrieve service");

        let (binder_died, _recipient) = register_death_notification(&mut remote);

        drop(service_process);
        remote
            .ping_binder()
            .expect_err("Service should have died already");

        assert!(
            binder_died.load(Ordering::Relaxed),
            "Did not receive death notification"
        );
    }

    /// Test unregistering death notifications.
    #[test]
    fn test_unregister_death_notifications() {
        binder::ProcessState::start_thread_pool();

        let service_name = "test_unregister_death_notifications";
        let service_process = ScopedServiceProcess::new(service_name);
        let mut remote = binder::get_service(service_name).expect("Could not retrieve service");

        let (binder_died, mut recipient) = register_death_notification(&mut remote);

        remote
            .unlink_to_death(&mut recipient)
            .expect("Could not unlink death notifications");

        drop(service_process);
        remote
            .ping_binder()
            .expect_err("Service should have died already");

        assert!(
            !binder_died.load(Ordering::Relaxed),
            "Received unexpected death notification after unlinking",
        );
    }

    /// Dropping a remote handle should unregister any death notifications.
    #[test]
    fn test_death_notification_registration_lifetime() {
        binder::ProcessState::start_thread_pool();

        let service_name = "test_death_notification_registration_lifetime";
        let service_process = ScopedServiceProcess::new(service_name);
        let mut remote = binder::get_service(service_name).expect("Could not retrieve service");

        let (binder_died, _recipient) = register_death_notification(&mut remote);

        // This should automatically unregister our death notification.
        drop(remote);

        drop(service_process);

        // We dropped the remote handle, so we should not receive the death
        // notification when the remote process dies here.
        assert!(
            !binder_died.load(Ordering::Relaxed),
            "Received unexpected death notification after dropping remote handle"
        );
    }
}
