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

#[macro_use]
extern crate lazy_static;

// shared between this test runner and shellcmd_service to test across processes
mod shellcmd;

use binder::declare_binder_interface;
use binder::interfaces::{BpServiceManager, IServiceManager};
use binder::parcel::Parcel;
use binder::service_manager::{DumpFlags, ServiceManager};
use binder::{Binder, IBinder, Interface, ProcessState, Service, String16};
use binder::{TransactionCode, TransactionFlags};

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};

// Path to executable depends on the test configuration in AndroidTest.xml.
const SHELLCMD_SERVICE_EXECUTABLE_PATH: &'static str =
    "/data/local/tmp/rustBinderShellcmdTestService";

lazy_static! {
    static ref LOCAL_SHELLCMD_SERVICE_RUNNING: bool =
        { shellcmd::start_service(shellcmd::SERVICE_LOCAL).is_ok() };
}

#[test]
fn servicemanager_get_interface() {
    let sm: BpServiceManager =
        binder::get_service("manager").expect("Did not get manager binder service");
    assert_eq!(
        sm.get_interface_descriptor().to_string(),
        "android.os.IServiceManager"
    );
}

#[derive(Default)]
struct ShellResult {
    code: i32,
    set: bool,
}

fn run_shellcmd(test_service: &mut Interface, args: &[&str]) -> String {
    let (mut in_files, mut out_files, mut err_files) = unsafe {
        let mut fds = [-1; 2];
        assert_eq!(
            0,
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        );
        let in_files = (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1]));

        let mut fds = [-1; 2];
        assert_eq!(
            0,
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        );
        let out_files = (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1]));

        let mut fds = [-1; 2];
        assert_eq!(
            0,
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        );
        let err_files = (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1]));

        (in_files, out_files, err_files)
    };

    let args: Vec<String16> = args.into_iter().map(|s| (*s).into()).collect();

    let result = Arc::new((Mutex::new(ShellResult::default()), Condvar::new()));
    let callback_result = result.clone();

    let error = test_service.shell_command(
        &mut in_files.0,
        &mut out_files.0,
        &mut err_files.0,
        &args,
        |_path, _se_context, _mode| None,
        move |code| {
            let (lock, cvar) = &*callback_result;
            let mut result = lock.lock().expect("Could not unlock result");
            *result = ShellResult { code, set: true };
            cvar.notify_one();
        },
    );
    assert!(error.is_ok());

    let (lock, cvar) = &*result;
    let result = lock.lock().expect("Could not unlock for wait");
    let result = if !result.set {
        cvar.wait(result)
            .expect("Could not unlock result after shell command")
    } else {
        result
    };
    assert_eq!(result.set, true);
    assert_eq!(result.code, 0);
    drop(out_files.0);

    let mut ret = String::new();
    out_files
        .1
        .read_to_string(&mut ret)
        .expect("Could not read from remote file");
    ret
}

// Based on binder's NDK unit test UseHandleShellCommand.
#[test]
fn test_shellcmd_local() {
    assert!(*LOCAL_SHELLCMD_SERVICE_RUNNING);
    let sm = ServiceManager::default();
    let mut test_service = sm
        .get_service(shellcmd::SERVICE_LOCAL)
        .expect("Could not connect to local test service");
    assert_eq!("", run_shellcmd(&mut test_service, &[]));
    assert_eq!("", run_shellcmd(&mut test_service, &["", ""]));
    assert_eq!(
        "Hello world!",
        run_shellcmd(&mut test_service, &["Hello ", "world!"])
    );
    assert_eq!("CMD", run_shellcmd(&mut test_service, &["C", "M", "D"]));
}

// Based on binder's NDK unit test UseHandleShellCommand.
#[test]
fn test_shellcmd_remote() {
    let mut server_process = Command::new(SHELLCMD_SERVICE_EXECUTABLE_PATH)
        .spawn()
        .expect("Could not start shellcmd test service");
    let sm = ServiceManager::default();
    let mut test_service = sm
        .get_service(shellcmd::SERVICE_REMOTE)
        .expect("Could not connect to remote test service");
    assert_eq!("", run_shellcmd(&mut test_service, &[]));
    assert_eq!("", run_shellcmd(&mut test_service, &["", ""]));
    assert_eq!(
        "Hello world!",
        run_shellcmd(&mut test_service, &["Hello ", "world!"])
    );
    assert_eq!("CMD", run_shellcmd(&mut test_service, &["C", "M", "D"]));
    server_process
        .kill()
        .expect("Could not stop shellcmd child process");
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
        if let Some(reply) = reply {
            reply.write_utf8_as_utf16(TestService::test())?;
        }
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
