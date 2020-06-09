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

//! Direct port of binderLibTest.cpp from libbinder to the Rust binder API

// Mutex<bool> is used with a Condvar and must be a mutex
#![allow(clippy::mutex_atomic, missing_docs)]

use binder::parcel::{Parcel, ParcelFileDescriptor};
use binder::Result as BinderResult;
use binder::Status as BinderStatus;
use binder::{
    declare_binder_interface, Binder, DeathRecipient, IBinder, Interface, ProcessState, SpIBinder,
    StatusCode, ThreadState, WpIBinder,
};
use libc::pipe2;

use std::convert::{TryFrom, TryInto};
use std::env::args;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::{replace, size_of, size_of_val};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::{self, exit, Child, Command};
use std::ptr;
use std::str;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::Duration;

macro_rules! tests {
    ($($test_name:ident $(: $modifier:ident)?,)+) => {{
        let mut tests = Vec::new();

        $(
            #[allow(unused_mut)]
            let mut skipped = false;

            $(
                if stringify!($modifier) == "Skip" {
                    skipped = true;
                }
            )?

            let test_name = stringify!($test_name);

            tests.push(Test {
                method: Self::$test_name,
                test_name,
                skipped,
            });
        )+

        tests
    }}
}

impl TestRunner {
    fn tests() -> Vec<Test> {
        tests! {
            test_nop_transaction,
            // SetError: Rust API doesn't expose the parcel error state.
            test_get_id,
            test_ptr_size,
            // IndirectGetId2, IndirectGetId3: We can't copy Parcel data out via
            // the Rust API, so we can't forward arbitrary, unstructured parcel
            // contents needed for indirect transactions.
            test_callback,
            test_add_server,
            test_death_notification_strong_ref,
            test_death_notification_multiple,
            test_death_notification_thread,
            // PassFile: Rust API only exposes passing files as
            // ParcelFileDescriptors.
            test_pass_file_descriptor,
            test_promote_local,
            test_local_get_extension,
            test_remote_get_extension,
            // CheckHandleZeroBinderHighBitsZeroCookie, FeedBinder: Require
            // flat_binder_object, which is not part of the Rust API.

            // CheckNoHeaderMappedInUser: Requires indirect transactions which
            // we can't do via the Rust API (see IndirectGetId*).

            // OnewayQueueing: Requires polling based server, which is not
            // currently supported in the Rust API.

            // WorkSource*, PropagateFlag*, SchedPolicySet: Require low-level
            // access to IPCThreadState APIs which are not provided by the Rust
            // API.
            test_vector_sent,
        }
    }
}

fn stdout_is_tty() -> bool {
    static mut IS_TTY: bool = false;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| IS_TTY = libc::isatty(libc::STDOUT_FILENO) != 0);

        // Weirdly, atest reports it is a tty but running the test manually via shell
        // reports it isn't a tty. But the opposite is expected, so we invert the value here.
        !IS_TTY
    }
}

use TransactionCode::*;

#[derive(Debug, PartialEq)]
#[repr(u32)]
enum TransactionCode {
    NopTransaction = SpIBinder::FIRST_CALL_TRANSACTION,
    RegisterServer,
    AddServer,
    AddPollServer,
    Callback,
    CallbackVerifyBuf,
    DelayedCallBack,
    NopCallback,
    GetSelfTransaction,
    GetIdTransaction,
    IndirectTransaction,
    GetStatusTransaction = SpIBinder::FIRST_CALL_TRANSACTION + 12,
    AddStrongRefTransaction,
    LinkDeathTransaction,
    WriteFileDescriptorTransaction,
    WriteFileTransaction,
    ExitTransaction,
    DelayedExitTransaction,
    GetPtrSizeTransaction,
    CreateBinderTransaction,
    EchoVector,
}

impl TryFrom<u32> for TransactionCode {
    type Error = StatusCode;

    fn try_from(code: u32) -> Result<Self, Self::Error> {
        const CALL_TRANSACTION: u32 = SpIBinder::FIRST_CALL_TRANSACTION;
        const REGISTER_SERVER: u32 = CALL_TRANSACTION + 1;
        const ADD_SERVER: u32 = CALL_TRANSACTION + 2;
        const ADD_POLL_SERVER: u32 = CALL_TRANSACTION + 3;
        const CALLBACK: u32 = CALL_TRANSACTION + 4;
        const CALLBACK_VERIFY_BUF: u32 = CALL_TRANSACTION + 5;
        const DELAYED_CALLBACK: u32 = CALL_TRANSACTION + 6;
        const NOP_CALLBACK: u32 = CALL_TRANSACTION + 7;
        const GET_SELF_TRANSACTION: u32 = CALL_TRANSACTION + 8;
        const GET_ID_TRANSACTION: u32 = CALL_TRANSACTION + 9;
        const INDIRECT_TRANSACTION: u32 = CALL_TRANSACTION + 10;
        const GET_STATUS_TRANSACTION: u32 = CALL_TRANSACTION + 12;
        const ADD_STRONG_REF_TRANSACTION: u32 = CALL_TRANSACTION + 13;
        const LINK_DEATH_TRANSACTION: u32 = CALL_TRANSACTION + 14;
        const WRITE_FILE_DESCRIPTOR_TRANSACTION: u32 = CALL_TRANSACTION + 15;
        const WRITE_FILE_TRANSACTION: u32 = CALL_TRANSACTION + 16;
        const EXIT_TRANSACTION: u32 = CALL_TRANSACTION + 17;
        const DELAYED_EXIT_TRANSACTION: u32 = CALL_TRANSACTION + 18;
        const GET_PTR_SIZED_TRANSACTION: u32 = CALL_TRANSACTION + 19;
        const CREATE_BINDER_TRANSACTION: u32 = CALL_TRANSACTION + 20;
        const ECHO_VECTOR: u32 = CALL_TRANSACTION + 21;

        Ok(match code {
            CALL_TRANSACTION => Self::NopTransaction,
            REGISTER_SERVER => Self::RegisterServer,
            ADD_SERVER => Self::AddServer,
            ADD_POLL_SERVER => Self::AddPollServer,
            CALLBACK => Self::Callback,
            CALLBACK_VERIFY_BUF => Self::CallbackVerifyBuf,
            DELAYED_CALLBACK => Self::DelayedCallBack,
            NOP_CALLBACK => Self::NopCallback,
            GET_SELF_TRANSACTION => Self::GetSelfTransaction,
            GET_ID_TRANSACTION => Self::GetIdTransaction,
            INDIRECT_TRANSACTION => Self::IndirectTransaction,
            GET_STATUS_TRANSACTION => Self::GetStatusTransaction,
            ADD_STRONG_REF_TRANSACTION => Self::AddStrongRefTransaction,
            LINK_DEATH_TRANSACTION => Self::LinkDeathTransaction,
            WRITE_FILE_DESCRIPTOR_TRANSACTION => Self::WriteFileDescriptorTransaction,
            WRITE_FILE_TRANSACTION => Self::WriteFileTransaction,
            EXIT_TRANSACTION => Self::ExitTransaction,
            DELAYED_EXIT_TRANSACTION => Self::DelayedExitTransaction,
            GET_PTR_SIZED_TRANSACTION => Self::GetPtrSizeTransaction,
            CREATE_BINDER_TRANSACTION => Self::CreateBinderTransaction,
            ECHO_VECTOR => Self::EchoVector,
            _ => return Err(StatusCode::UNKNOWN_TRANSACTION),
        })
    }
}

#[derive(Debug)]
struct TestEnv {
    test_service_name: String,
    binder_server_suffix: String,
    bin_path: String,
}

struct Server {
    test_env: TestEnv,
    m_id: i32,
    m_next_server_id: AtomicI32,
    m_server_start_requested: Mutex<bool>,
    m_server_wait_cond: Condvar,
    m_server_started: Mutex<Option<SpIBinder>>,
    m_strong_ref: Mutex<Option<SpIBinder>>,
}

impl Server {
    fn new(m_id: i32, test_env: TestEnv) -> Self {
        Server {
            test_env,
            m_id,
            m_next_server_id: AtomicI32::new(m_id + 1),
            m_server_start_requested: Mutex::new(false),
            m_server_wait_cond: Condvar::new(),
            m_server_started: Mutex::new(None),
            m_strong_ref: Mutex::new(None),
        }
    }

    fn run(mut self, _readpipefd: RawFd) -> Result<(), Box<dyn Error>> {
        self.test_env
            .test_service_name
            .push_str(&self.test_env.binder_server_suffix);

        let test_service_name = self.test_env.test_service_name.clone();
        let m_id = self.m_id;

        {
            let mut binder_native = Binder::new(BnBinderLibService(Box::new(self)));

            // Normally would also contain functionality as well, but we are only
            // testing the extension mechanism.
            binder_native
                .set_extension(&mut Binder::new(()).as_binder())
                .expect("Could not set extension to service");

            if m_id == 0 {
                binder::add_service(&test_service_name, binder_native.as_binder())?;
            } else {
                let server = binder::get_interface::<dyn IBinderLibService>(&test_service_name)?;

                let _reply = server.register_server(m_id, binder_native.as_binder());
            }
        }

        ProcessState::start_thread_pool();
        ProcessState::join_thread_pool();

        unreachable!("join_thread_pool should never return");
    }
}

pub trait IBinderLibService: Interface {
    fn register_server(&self, id: i32, server: SpIBinder) -> BinderResult<()>;

    fn add_server(&self) -> BinderResult<(SpIBinder, i32)>;

    fn nop(&self) -> BinderResult<()>;

    fn nop_callback(&self, binder: SpIBinder) -> BinderResult<()>;

    fn get_id(&self) -> BinderResult<i32>;

    fn get_ptr_size(&self) -> BinderResult<i32>;

    fn get_status(&self) -> BinderResult<()>;

    fn add_strong_ref(&self, binder: SpIBinder) -> BinderResult<()>;

    fn link_death(&self, target: &mut SpIBinder, callback: SpIBinder) -> BinderResult<()>;

    fn write_file_descriptor(
        &self,
        file: Option<ParcelFileDescriptor>,
        buf: &[u8],
    ) -> BinderResult<()>;

    fn delayed_exit(&self) -> BinderResult<()>;

    fn exit(&self) -> BinderResult<()>;

    fn create_binder(&self) -> BinderResult<SpIBinder>;

    fn echo_vector(&self, vector: &[u64]) -> BinderResult<Vec<u64>>;

    fn callback(&self) -> BinderResult<()>;
}

impl Interface for Server {}

impl IBinderLibService for Server {
    fn register_server(&self, _id: i32, server: SpIBinder) -> BinderResult<()> {
        if self.m_id != 0 {
            return Err(StatusCode::INVALID_OPERATION);
        }

        let mut server_start_requested = self.m_server_start_requested.lock().unwrap();

        if *server_start_requested {
            *server_start_requested = false;
            *self.m_server_started.lock().unwrap() = Some(server);
            self.m_server_wait_cond.notify_all();
        }

        Ok(())
    }

    fn add_server(&self) -> BinderResult<(SpIBinder, i32)> {
        let server_id;

        if self.m_id != 0 {
            return Err(StatusCode::INVALID_OPERATION);
        }

        let mut server_start_requested = self.m_server_start_requested.lock().unwrap();

        if *server_start_requested {
            return Err(StatusCode::INVALID_OPERATION);
        } else {
            server_id = self.m_next_server_id.fetch_add(1, Ordering::SeqCst);

            *server_start_requested = true;

            drop(server_start_requested);
            start_server_process(server_id, &self.test_env)?;
            server_start_requested = self.m_server_start_requested.lock().unwrap();
        }

        // Wait for the service to register
        if *server_start_requested {
            let (lock, _) = self
                .m_server_wait_cond
                .wait_timeout(server_start_requested, Duration::from_secs(5))
                .unwrap();

            server_start_requested = lock;
        }

        if *server_start_requested {
            *server_start_requested = false;
            Err(StatusCode::TIMED_OUT)
        } else {
            let mut server_started = self.m_server_started.lock().unwrap();
            let server = server_started
                .take()
                .expect("Server should have been started");
            Ok((server, server_id))
        }
    }

    fn nop(&self) -> BinderResult<()> {
        Ok(())
    }

    fn nop_callback(&self, binder: SpIBinder) -> BinderResult<()> {
        let callback_object: Box<dyn ICallback> = binder.into_interface()?;
        callback_object.callback(BinderStatus::ok())
    }

    fn get_id(&self) -> BinderResult<i32> {
        Ok(self.m_id)
    }

    fn get_ptr_size(&self) -> BinderResult<i32> {
        Ok(size_of::<usize>().try_into().unwrap())
    }

    fn get_status(&self) -> BinderResult<()> {
        Ok(())
    }

    fn add_strong_ref(&self, binder: SpIBinder) -> BinderResult<()> {
        *self.m_strong_ref.lock().unwrap() = Some(binder);
        Ok(())
    }

    fn link_death(&self, target: &mut SpIBinder, callback: SpIBinder) -> BinderResult<()> {
        let event = Arc::new(TestEvent::new());
        let inner_event = event.clone();
        let mut death_recipient = DeathRecipient::new(move || inner_event.trigger_event());
        let ret = target.link_to_death(&mut death_recipient);

        if ret.is_ok() {
            event.wait_event(5)?;
        }

        callback
            .into_interface::<dyn ICallback>()?
            .callback(ret.map_or_else(|e| e.into(), |_| BinderStatus::ok()))
    }

    fn write_file_descriptor(
        &self,
        file: Option<ParcelFileDescriptor>,
        buf: &[u8],
    ) -> BinderResult<()> {
        if buf.is_empty() {
            return Err(StatusCode::BAD_VALUE);
        }

        let mut file: File = file.unwrap().into();
        let result = file.write(buf);

        match result {
            Ok(bytes_written) if bytes_written == buf.len() => Ok(()),
            _ => Err(StatusCode::UNKNOWN_ERROR),
        }
    }

    fn delayed_exit(&self) -> BinderResult<()> {
        unsafe { libc::alarm(10) };
        Ok(())
    }

    fn exit(&self) -> BinderResult<()> {
        while unsafe { libc::wait(ptr::null_mut()) != -1 || *libc::__errno() != libc::ECHILD } {}

        exit(0);
    }

    fn create_binder(&self) -> BinderResult<SpIBinder> {
        Ok(Binder::new(()).as_binder())
    }

    fn echo_vector(&self, vector: &[u64]) -> BinderResult<Vec<u64>> {
        Ok(vector.to_vec())
    }

    fn callback(&self) -> BinderResult<()> {
        Err(StatusCode::UNKNOWN_ERROR)
    }
}

declare_binder_interface! {
    IBinderLibService["test.binderLib"] {
        native: BnBinderLibService(on_transact),
        proxy: BpBinderLibService,
    }
}

impl IBinderLibService for Binder<BnBinderLibService> {
    fn register_server(&self, id: i32, server: SpIBinder) -> BinderResult<()> {
        self.0.register_server(id, server)
    }

    fn add_server(&self) -> BinderResult<(SpIBinder, i32)> {
        self.0.add_server()
    }

    fn nop(&self) -> BinderResult<()> {
        self.0.nop()
    }

    fn nop_callback(&self, binder: SpIBinder) -> BinderResult<()> {
        self.0.nop_callback(binder)
    }

    fn get_id(&self) -> BinderResult<i32> {
        self.0.get_id()
    }

    fn get_ptr_size(&self) -> BinderResult<i32> {
        self.0.get_ptr_size()
    }

    fn get_status(&self) -> BinderResult<()> {
        self.0.get_status()
    }

    fn add_strong_ref(&self, binder: SpIBinder) -> BinderResult<()> {
        self.0.add_strong_ref(binder)
    }

    fn link_death(&self, target: &mut SpIBinder, callback: SpIBinder) -> BinderResult<()> {
        self.0.link_death(target, callback)
    }

    fn write_file_descriptor(
        &self,
        file: Option<ParcelFileDescriptor>,
        buf: &[u8],
    ) -> BinderResult<()> {
        self.0.write_file_descriptor(file, buf)
    }

    fn delayed_exit(&self) -> BinderResult<()> {
        self.0.delayed_exit()
    }

    fn exit(&self) -> BinderResult<()> {
        self.0.exit()
    }

    fn create_binder(&self) -> BinderResult<SpIBinder> {
        self.0.create_binder()
    }

    fn echo_vector(&self, vector: &[u64]) -> BinderResult<Vec<u64>> {
        self.0.echo_vector(vector)
    }

    fn callback(&self) -> BinderResult<()> {
        self.0.callback()
    }
}

impl IBinderLibService for BpBinderLibService {
    fn register_server(&self, id: i32, server: SpIBinder) -> BinderResult<()> {
        self.as_binder()
            .transact(RegisterServer as u32, 0, |data| {
                data.write(&id)?;
                data.write(&server)
            })?;
        Ok(())
    }

    fn add_server(&self) -> BinderResult<(SpIBinder, i32)> {
        let reply = self.as_binder().transact(AddServer as u32, 0, |_| Ok(()))?;
        let binder: SpIBinder = reply.read()?;
        let id: i32 = reply.read()?;
        Ok((binder, id))
    }

    fn nop(&self) -> BinderResult<()> {
        self.as_binder()
            .transact(NopTransaction as u32, 0, |_| Ok(()))?;
        Ok(())
    }

    fn nop_callback(&self, binder: SpIBinder) -> BinderResult<()> {
        self.as_binder()
            .transact(NopCallback as u32, Self::FLAG_ONEWAY, |data| {
                data.write(&binder)
            })?;
        Ok(())
    }

    fn get_id(&self) -> BinderResult<i32> {
        let reply = self
            .as_binder()
            .transact(GetIdTransaction as u32, 0, |_| Ok(()))?;
        reply.read()
    }

    fn get_ptr_size(&self) -> BinderResult<i32> {
        let reply = self
            .as_binder()
            .transact(GetPtrSizeTransaction as u32, 0, |_| Ok(()))?;
        reply.read()
    }

    fn get_status(&self) -> BinderResult<()> {
        self.as_binder()
            .transact(GetStatusTransaction as u32, 0, |_| Ok(()))?;
        Ok(())
    }

    fn add_strong_ref(&self, binder: SpIBinder) -> BinderResult<()> {
        self.as_binder()
            .transact(AddStrongRefTransaction as u32, Self::FLAG_ONEWAY, |data| {
                data.write(&binder)
            })?;
        Ok(())
    }

    fn link_death(&self, target: &mut SpIBinder, callback: SpIBinder) -> BinderResult<()> {
        self.as_binder()
            .transact(LinkDeathTransaction as u32, Self::FLAG_ONEWAY, |data| {
                data.write(target)?;
                data.write(&callback)?;
                Ok(())
            })?;
        Ok(())
    }

    fn write_file_descriptor(
        &self,
        file: Option<ParcelFileDescriptor>,
        buf: &[u8],
    ) -> BinderResult<()> {
        self.as_binder()
            .transact(WriteFileDescriptorTransaction as u32, 0, |data| {
                data.write(&file)?;
                data.write(buf)?;
                Ok(())
            })?;
        Ok(())
    }

    fn delayed_exit(&self) -> BinderResult<()> {
        self.as_binder()
            .transact(DelayedExitTransaction as u32, 0, |_| Ok(()))?;
        Ok(())
    }

    fn exit(&self) -> BinderResult<()> {
        self.as_binder()
            .transact(ExitTransaction as u32, Self::FLAG_ONEWAY, |_| Ok(()))?;
        Ok(())
    }

    fn create_binder(&self) -> BinderResult<SpIBinder> {
        let reply = self
            .as_binder()
            .transact(CreateBinderTransaction as u32, 0, |_| Ok(()))?;
        reply.read()
    }

    fn echo_vector(&self, vector: &[u64]) -> BinderResult<Vec<u64>> {
        let reply = self
            .as_binder()
            .transact(EchoVector as u32, 0, |data| data.write(vector))?;
        reply.read()
    }

    fn callback(&self) -> BinderResult<()> {
        self.as_binder().transact(Callback as u32, 0, |_| Ok(()))?;
        Ok(())
    }
}

fn on_transact(
    service: &dyn IBinderLibService,
    code: u32,
    data: &Parcel,
    reply: &mut Parcel,
) -> BinderResult<()> {
    let uid = unsafe { libc::getuid() };
    let calling_uid = ThreadState::get_calling_uid();

    if uid != calling_uid {
        return Err(StatusCode::PERMISSION_DENIED);
    }

    let code = TransactionCode::try_from(code)?;

    use TransactionCode::*;

    match code {
        RegisterServer => {
            let id: i32 = data.read()?;
            let binder: SpIBinder = data.read().map_err(|_| StatusCode::BAD_VALUE)?;
            service.register_server(id, binder)
        }
        AddPollServer | AddServer => {
            let (server, server_id) = service.add_server()?;
            reply.write(&server)?;
            reply.write(&server_id)?;
            Ok(())
        }
        NopTransaction => service.nop(),
        DelayedCallBack => {
            unimplemented!("This transaction is only designed for use with a poll() server, which we don't support in Rust.");
        }
        NopCallback => {
            let binder: SpIBinder = data.read().or(Err(StatusCode::BAD_VALUE))?;

            service.nop_callback(binder)
        }
        GetSelfTransaction => {
            // self.serialize(&mut reply); // Disregards error?
            unimplemented!()
        }
        GetIdTransaction => reply.write(&service.get_id()?),
        IndirectTransaction => {
            unimplemented!("Indirect transactions rely on being able to copy arbitrary Parcel ranges, which is not supported in Rust.")
        }
        GetPtrSizeTransaction => {
            let size = service.get_ptr_size()?;
            reply.write(&size)?;
            Ok(())
        }
        GetStatusTransaction => service.get_status(),
        AddStrongRefTransaction => {
            let binder = data.read()?;
            service.add_strong_ref(binder)
        }
        LinkDeathTransaction => {
            let mut target: SpIBinder = data.read()?;
            let callback: SpIBinder = data.read()?;
            service.link_death(&mut target, callback)
        }
        WriteFileDescriptorTransaction => {
            let file: Option<ParcelFileDescriptor> = data.read()?;
            let buf: Vec<u8> = data.read()?;
            service.write_file_descriptor(file, &buf)
        }
        WriteFileTransaction => unimplemented!("libbinder_ndk only supports ParcelFileDescriptors"),
        DelayedExitTransaction => service.delayed_exit(),
        ExitTransaction => service.exit(),
        CreateBinderTransaction => reply.write(&service.create_binder()?),
        EchoVector => {
            let vector: Vec<u64> = data.read()?;
            reply.write(&service.echo_vector(&vector)?)
        }
        Callback | CallbackVerifyBuf => service.callback(),
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        exit(0);
    }
}

const RED_FG: &str = "\x1B[38;5;1m";
const GREEN_FG: &str = "\x1B[38;5;2m";
const YELLOW_FG: &str = "\x1B[38;5;3m";
const MAGENTA_FG: &str = "\x1B[38;5;5m";
const CLEAR: &str = "\x1B[0m";

#[derive(Debug)]
enum TestStatus {
    Passed,
    Skipped,
    Failed(TestError),
}

struct TestOutcome {
    status: TestStatus,
    test_name: &'static str,
}

impl Display for TestOutcome {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let is_tty = stdout_is_tty();

        f.write_str("test ")?;
        f.write_str(self.test_name)?;
        f.write_str(" ... ")?;

        match &self.status {
            TestStatus::Passed => {
                if is_tty {
                    f.write_str(GREEN_FG)?;
                }

                f.write_str("ok")?;

                if is_tty {
                    f.write_str(CLEAR)?;
                }

                Ok(())
            }
            TestStatus::Skipped => {
                if is_tty {
                    f.write_str(YELLOW_FG)?;
                }

                f.write_str("ignored")?;

                if is_tty {
                    f.write_str(CLEAR)?;
                }
                Ok(())
            }
            TestStatus::Failed(e, ..) => {
                if is_tty {
                    f.write_str(RED_FG)?;
                }

                f.write_str("FAILED")?;

                if is_tty {
                    f.write_str(CLEAR)?;
                }

                f.write_str("\n - ")?;
                write!(f, "{}", e)
            }
        }
    }
}

#[derive(Debug)]
enum TestErrorKind {
    // The resut of an assertion failure.
    Assert,
    // The result of a `BinderError` failure
    Error(BinderStatus),
    // The result of a `test_unimplemented!` invocation.
    #[allow(dead_code)]
    Unimplemented,
}

#[derive(Debug)]
struct TestError {
    kind: TestErrorKind,
    line: u32,
    src: &'static str,
}

impl Display for TestError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}L{}{}: ", MAGENTA_FG, self.line, CLEAR)?;

        match &self.kind {
            TestErrorKind::Assert => write!(f, "test_assert!({})", self.src),
            TestErrorKind::Error(e) => write!(f, "{} == {}", self.src, e),
            TestErrorKind::Unimplemented => f.write_str(self.src),
        }
    }
}

impl From<BinderStatus> for TestErrorKind {
    fn from(e: BinderStatus) -> Self {
        TestErrorKind::Error(e)
    }
}

impl From<StatusCode> for TestErrorKind {
    fn from(e: StatusCode) -> Self {
        TestErrorKind::Error(e.into())
    }
}

/// Like the `unimplemented!()` macro but fails a test rather than `panic!`-ing.
#[allow(unused_macros)]
macro_rules! test_unimplemented {
    () => {
        return Err(TestError {
            kind: TestErrorKind::Unimplemented,
            line: line!(),
            src: "test_unimplemented!()",
        });
    };
}

/// Like the `?` operator, but usable within tests so that failures can be reported.
macro_rules! test_try {
    ($result:expr) => {
        match $result {
            Ok(ok) => ok,
            Err(e) => {
                let src = stringify!($result);

                return Err(TestError {
                    kind: e.into(),
                    line: line!(),
                    src,
                });
            }
        }
    };
}

/// Like the `assert!` macro but fails a test rather than `panic!`-ing".
macro_rules! test_assert {
    ($assertion:expr) => {
        if !$assertion {
            let src = stringify!($assertion);

            return Err(TestError {
                kind: TestErrorKind::Assert,
                line: line!(),
                src,
            });
        }
    };
}

/// Like the `assert_eq!` macro but fails a test rather than `panic!`-ing.
macro_rules! test_assert_eq {
    ($lhs:expr, $rhs:expr) => {
        test_assert!($lhs == $rhs)
    };
}

type TestResult = Result<(), TestError>;

struct Test {
    method: fn(&mut TestRunner) -> TestResult,
    test_name: &'static str,
    skipped: bool,
}

impl Display for Test {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}: test", self.test_name)
    }
}

struct TestRunner {
    m_server: Box<dyn IBinderLibService>,
    server_process: Child,
    tests: Vec<Test>,
}

impl TestRunner {
    fn try_new(test_env: TestEnv) -> BinderResult<Self> {
        let server_process = start_server_process(0, &test_env)?;
        let m_server = binder::get_interface::<dyn IBinderLibService>(&test_env.test_service_name)?;

        Ok(TestRunner {
            m_server,
            server_process,
            tests: Self::tests(),
        })
    }

    fn run_all_tests(mut self) -> Vec<TestOutcome> {
        let mut outcomes = Vec::with_capacity(self.tests.len());
        let tests = replace(&mut self.tests, Vec::new());

        for test in tests {
            let status = if test.skipped {
                TestStatus::Skipped
            } else {
                match (test.method)(&mut self) {
                    Ok(()) => TestStatus::Passed,
                    Err(e) => TestStatus::Failed(e),
                }
            };

            outcomes.push(TestOutcome {
                status,
                test_name: test.test_name,
            });
        }

        outcomes
    }

    fn add_server(&mut self, _is_poll: bool) -> BinderResult<(SpIBinder, i32)> {
        self.m_server.add_server()
    }

    fn test_promote_local(&mut self) -> TestResult {
        let mut strong = Binder::new(());
        let weak = WpIBinder::new(&mut strong);
        let strong_from_weak = test_try!(weak.promote().ok_or(StatusCode::DEAD_OBJECT));

        test_assert_eq!(strong.as_binder(), strong_from_weak);

        drop(strong);
        drop(strong_from_weak);

        test_assert!(weak.promote().is_none());

        Ok(())
    }

    fn test_remote_get_extension(&mut self) -> TestResult {
        let (mut server, _id) = test_try!(self.add_server(false));
        let extension = test_try!(server.get_extension());

        test_try!(extension.unwrap().ping_binder());

        Ok(())
    }

    fn test_death_notification_multiple(&mut self) -> TestResult {
        const CLIENT_COUNT: usize = 2;

        let mut callbacks = Vec::with_capacity(CLIENT_COUNT);
        let mut linked_clients: Vec<Box<dyn IBinderLibService>> = Vec::with_capacity(CLIENT_COUNT);
        let mut passive_clients: Vec<Box<dyn IBinderLibService>> = Vec::with_capacity(CLIENT_COUNT);
        let target: Box<dyn IBinderLibService> =
            test_try!(test_try!(self.add_server(false)).0.into_interface());

        for i in 0..CLIENT_COUNT {
            {
                linked_clients.push(test_try!(test_try!(self.add_server(false))
                    .0
                    .into_interface()));
                callbacks.push(TestCallbackArc::new());

                test_try!(linked_clients[i].link_death(
                    &mut target.as_binder(),
                    BnCallback::new_binder(callbacks[i].clone()).as_binder()
                ));
            }
            {
                passive_clients.push(test_try!(test_try!(self.add_server(false))
                    .0
                    .into_interface()));

                test_try!(passive_clients[i].add_strong_ref(target.as_binder()));
            }
        }
        {
            test_try!(target.exit());
        }

        for callback in callbacks {
            test_try!(callback.wait_event(5));
            test_try!(callback.get_result());
        }

        Ok(())
    }

    fn test_death_notification_strong_ref(&mut self) -> TestResult {
        let event = Arc::new(TestEvent::new());
        let inner_event = event.clone();
        let mut death_recipient = DeathRecipient::new(move || inner_event.trigger_event());

        let sbinder: Box<dyn IBinderLibService> = {
            let mut binder = test_try!(self.add_server(false)).0;

            test_try!(binder.link_to_death(&mut death_recipient));
            test_try!(binder.into_interface())
        };
        {
            test_try!(sbinder.exit());
        }

        test_try!(event.wait_event(5));
        // The NDK AIBinder_DeathRecipient::TransferDeathRecipient::binderDied()
        // callback already calls unlinkToDeath and checks that it results in
        // DEAD_OBJECT, so we can't do that again here as the C++ test does.

        Ok(())
    }

    fn test_death_notification_thread(&mut self) -> TestResult {
        let callback = TestCallbackArc::new();
        let target: Box<dyn IBinderLibService> =
            test_try!(test_try!(self.add_server(false)).0.into_interface());
        let client: Box<dyn IBinderLibService> =
            test_try!(test_try!(self.add_server(false)).0.into_interface());
        let event = Arc::new(TestEvent::new());
        let inner_event = event.clone();
        let mut death_recipient = DeathRecipient::new(move || inner_event.trigger_event());

        test_try!(target.as_binder().link_to_death(&mut death_recipient));

        {
            test_try!(target.exit());
        }

        // Make sure it's dead
        test_try!(event.wait_event(5));

        // Now, pass the ref to another process and ask that process to
        // call linkToDeath() on it, and wait for a response. This tests
        // two things:
        // 1) You still get death notifications when calling link_to_death()
        //    on a ref that is already dead when it was passed to you.
        // 2) That death notifications are not directly pushed to the thread
        //    registering them, but to the threadpool (proc workqueue) instead.
        //
        // 2) is tested because the thread handling TransactionCode::LinkDeathTransaction
        // is blocked on a condition variable waiting for the death notification to be
        // called; therefore, that thread is not available for handling proc work.
        // So, if the death notification was pushed to the thread workqueue, the callback
        // would never be called, and the test would timeout and fail.
        //
        // Note that we can't do this part of the test from this thread itself, because
        // the binder driver would only push death notifications to the thread if
        // it is a looper thread, which this thread is not.
        //
        // See b/23525545 for details.
        {
            test_try!(client.link_death(
                &mut target.as_binder(),
                BnCallback::new_binder(callback.clone()).as_binder()
            ));
        }

        test_try!(callback.wait_event(5));
        test_try!(callback.get_result());

        Ok(())
    }

    fn test_pass_file_descriptor(&mut self) -> TestResult {
        let write_value = 123u8;
        let mut pipe_fds: [RawFd; 2] = [0, 0];
        let mut buf = [0];
        let ret = unsafe { pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK) };

        test_assert_eq!(ret, 0);

        // We will transfer ownership of the write fd to `data`, so we want
        // `data` to drop prior to blocking in `wait_for_read_data` so that it
        // closes the fd for us (client side).
        {
            let write_file = unsafe { File::from_raw_fd(pipe_fds[1]) };
            let write_buf = [write_value];

            test_try!(self
                .m_server
                .write_file_descriptor(Some(ParcelFileDescriptor::new(write_file)), &write_buf));
        }

        let mut file = unsafe { File::from_raw_fd(pipe_fds[0]) };

        let bytes_written = file.read(&mut buf).expect("to write to pipe");

        test_assert_eq!(bytes_written, size_of_val(&buf));
        test_assert_eq!(write_value, buf[0]);

        // Wait for other process to close pipe:
        self.wait_for_read_data(file.as_raw_fd(), 5000)?;

        let bytes_written = file.read(&mut buf).expect("to write to pipe");

        test_assert_eq!(bytes_written, 0);

        Ok(())
    }

    fn wait_for_read_data(&self, pipe_fd: RawFd, timeout_ms: libc::c_int) -> TestResult {
        let mut pfd = libc::pollfd {
            fd: pipe_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };

        test_assert_eq!(ret, 1);

        Ok(())
    }

    fn test_callback(&mut self) -> TestResult {
        let callback = TestCallbackArc::new();

        test_try!(self
            .m_server
            .nop_callback(BnCallback::new_binder(callback.clone()).as_binder()));

        test_try!(callback.wait_event(5));
        test_try!(callback.get_result());

        Ok(())
    }

    fn test_local_get_extension(&mut self) -> TestResult {
        let mut binder = Binder::new(());
        let ext = Binder::new(());

        test_assert!(binder.get_extension().unwrap().is_none());

        test_try!(binder.set_extension(&mut ext.as_binder()));

        test_assert_eq!(binder.get_extension().unwrap(), Some(ext.as_binder()));

        Ok(())
    }

    fn test_nop_transaction(&mut self) -> TestResult {
        test_try!(self.m_server.nop());

        Ok(())
    }

    fn test_get_id(&mut self) -> TestResult {
        test_assert_eq!(self.m_server.get_id(), Ok(0));

        Ok(())
    }

    fn test_ptr_size(&mut self) -> TestResult {
        let (server, _id) = test_try!(self.add_server(false));

        let server: Box<dyn IBinderLibService> = test_try!(server.into_interface());

        let ptr_size = test_try!(server.get_ptr_size());

        test_assert_eq!(ptr_size as usize, size_of::<usize>());

        Ok(())
    }

    fn test_add_server(&mut self) -> TestResult {
        test_try!(self.add_server(false).map(|_| ()));

        Ok(())
    }

    fn test_vector_sent(&mut self) -> TestResult {
        let (server, _id) = test_try!(self.add_server(false));
        let server: Box<dyn IBinderLibService> = test_try!(server.into_interface());
        let test_value = [u64::max_value(), 0, 200];

        let read_value = test_try!(server.echo_vector(&test_value));

        test_assert_eq!(read_value, test_value);

        Ok(())
    }
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        let interface = &mut self.m_server;

        assert_eq!(interface.get_status(), Ok(()));
        assert!(interface.exit().is_ok());

        let mut exit_status = 0;
        let pid = unsafe { libc::wait(&mut exit_status) };

        assert_eq!(pid, self.server_process.id().try_into().unwrap());

        unsafe {
            assert!(libc::WIFEXITED(exit_status));
            assert_eq!(libc::WEXITSTATUS(exit_status), 0);
        }
    }
}

struct TestCallback {
    test_event: TestEvent,
    m_result: Mutex<BinderResult<()>>,
}

#[derive(Clone)]
struct TestCallbackArc(Arc<TestCallback>);

impl TestCallbackArc {
    fn new() -> Self {
        Self(Arc::new(TestCallback::new()))
    }
}

impl Deref for TestCallbackArc {
    type Target = TestCallback;
    fn deref(&self) -> &TestCallback {
        self.0.deref()
    }
}

impl TestCallback {
    fn new() -> Self {
        TestCallback {
            test_event: TestEvent::new(),
            m_result: Mutex::new(Err(StatusCode::NOT_ENOUGH_DATA)),
        }
    }

    fn get_result(&self) -> BinderResult<()> {
        *self.m_result.lock().unwrap()
    }

    fn wait_event(&self, timeout_s: u64) -> BinderResult<()> {
        self.test_event.wait_event(timeout_s)
    }

    fn trigger_event(&self) {
        self.test_event.trigger_event()
    }
}

pub trait ICallback: Interface {
    fn callback(&self, status: BinderStatus) -> BinderResult<()>;
}

impl ICallback for TestCallbackArc {
    fn callback(&self, status: BinderStatus) -> BinderResult<()> {
        if status.is_ok() {
            *self.m_result.lock().unwrap() = Ok(());
        } else {
            *self.m_result.lock().unwrap() = Err(status.transaction_error());
        }
        self.trigger_event();
        Ok(())
    }
}

impl Interface for TestCallbackArc {}

declare_binder_interface! {
    ICallback["test.binderTestCallback"] {
        native: BnCallback(callback_on_transact),
        proxy: BpCallback,
    }
}

impl ICallback for Binder<BnCallback> {
    fn callback(&self, status: BinderStatus) -> BinderResult<()> {
        self.0.callback(status)
    }
}

impl ICallback for BpCallback {
    fn callback(&self, status: BinderStatus) -> BinderResult<()> {
        self.as_binder()
            .transact(Callback as u32, 0, |data| data.write(&status))?;
        Ok(())
    }
}

fn callback_on_transact(
    service: &dyn ICallback,
    code: u32,
    data: &Parcel,
    _reply: &mut Parcel,
) -> BinderResult<()> {
    let code = TransactionCode::try_from(code);

    match code {
        Ok(Callback) => {
            let status: BinderStatus = data.read()?;
            service.callback(status)
        }
        _ => Err(StatusCode::UNKNOWN_TRANSACTION),
    }
}

struct TestEvent {
    m_event_triggered: Mutex<bool>,
    m_wait_cond: Condvar,
}

impl TestEvent {
    fn new() -> Self {
        TestEvent {
            m_event_triggered: Mutex::new(false),
            m_wait_cond: Condvar::new(),
        }
    }

    fn wait_event(&self, timeout_s: u64) -> BinderResult<()> {
        let mut m_event_triggered = self.m_event_triggered.lock().unwrap();

        if !*m_event_triggered {
            let (lock, _) = self
                .m_wait_cond
                .wait_timeout(m_event_triggered, Duration::from_secs(timeout_s))
                .unwrap();

            m_event_triggered = lock;
        }

        if *m_event_triggered {
            Ok(())
        } else {
            Err(StatusCode::TIMED_OUT)
        }
    }

    fn trigger_event(&self) {
        let mut m_event_triggered = self.m_event_triggered.lock().unwrap();

        self.m_wait_cond.notify_all();

        *m_event_triggered = true;
    }
}

fn bytes_written(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or_else(|| bytes.len())
}

fn start_server_process(index: i32, test_env: &TestEnv) -> BinderResult<Child> {
    let mut index_bytes = [0u8; 11];

    write!(&mut index_bytes as &mut [u8], "{}", index).expect("i32 to always fit in 11 bytes");

    let bytes_written = bytes_written(&index_bytes);
    let index_str = str::from_utf8(&index_bytes[..bytes_written]).unwrap();
    let child = Command::new(&test_env.bin_path)
        .arg("--binderserver")
        .arg(index_str)
        .arg(&test_env.binder_server_suffix)
        .spawn()
        .map_err(|_| StatusCode::DEAD_OBJECT)?;

    Ok(child)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = args();
    let bin_path = args.next().expect("Path arg should exist");
    let mut binder_server_suffix = [0u8; 16];
    let mut env = TestEnv {
        test_service_name: "test.binderLib".to_string(),
        binder_server_suffix: String::new(),
        bin_path,
    };
    let first_arg = args.next();

    // Display the test count so that the trade federation can parse it.
    if let Some("--list") = first_arg.as_deref() {
        let tests = TestRunner::tests();
        for test in &tests {
            println!("{}", test);
        }
        println!();
        println!("{} tests, 0 benchmarks", tests.len());

        return Ok(());
    }

    if let Some("--binderserver") = first_arg.as_deref() {
        let args = (args.next(), args.next());

        if let (Some(index), Some(server_suffix)) = args {
            let index = index.parse().expect("To find a valid id");

            env.binder_server_suffix = server_suffix;

            return Server::new(index, env).run(0);
        }
    }

    write!(&mut binder_server_suffix as &mut [u8], "{}", process::id())?;

    // Trimming the end of the slice so null bytes aren't appended.
    let first_zero = bytes_written(&binder_server_suffix);

    env.binder_server_suffix = str::from_utf8(&binder_server_suffix[..first_zero])?.to_string();
    env.test_service_name.push_str(&env.binder_server_suffix);

    ProcessState::start_thread_pool();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    let runner = TestRunner::try_new(env)?;

    for test_outcome in runner.run_all_tests() {
        println!("{}", test_outcome);

        match test_outcome.status {
            TestStatus::Passed => passed += 1,
            TestStatus::Skipped => skipped += 1,
            TestStatus::Failed(..) => failed += 1,
        }
    }

    let status = if failed > 0 {
        [RED_FG, "FAILED", CLEAR]
    } else {
        [GREEN_FG, "ok", CLEAR]
    }
    .join("");

    println!(
        "\ntest result: {}. {} passed; {} failed; {} ignored;",
        status, passed, failed, skipped
    );

    Ok(())
}
