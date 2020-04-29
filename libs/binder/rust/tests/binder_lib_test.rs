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

use binder::parcel::{Parcel, Parcelable};
use binder::prelude::*;
use binder::service_manager::{DumpFlags, ServiceManager};
use binder::{
    binder_status, Binder, DeathRecipient, DeathRecipientCallback, IBinder, Interface,
    ProcessState, Service, ThreadState, WeakInterface,
};
use libc::pipe2;

use std::convert::{TryFrom, TryInto};
use std::env::args;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::{replace, size_of, size_of_val, ManuallyDrop, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::{self, exit, Child, Command};
use std::ptr;
use std::str;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Condvar, Mutex, Once};
use std::thread::sleep;
use std::time::Duration;

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
    NopTransaction = Interface::FIRST_CALL_TRANSACTION,
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
    SetErrorTransaction,
    GetStatusTransaction,
    AddStrongRefTransaction,
    LinkDeathTransaction,
    WriteFileDescriptorTransaction,
    WriteFileTransaction,
    ExitTransaction,
    DelayedExitTransaction,
    GetPtrSizeTransaction,
    CreateBinderTransaction,
    GetWorkSourceTransaction,
    EchoVector,
}

impl TryFrom<u32> for TransactionCode {
    type Error = BinderError;

    fn try_from(code: u32) -> Result<Self, Self::Error> {
        const CALL_TRANSACTION: u32 = Interface::FIRST_CALL_TRANSACTION;
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
        const SET_ERROR_TRANSACTION: u32 = CALL_TRANSACTION + 11;
        const GET_STATUS_TRANSACTION: u32 = CALL_TRANSACTION + 12;
        const ADD_STRONG_REF_TRANSACTION: u32 = CALL_TRANSACTION + 13;
        const LINK_DEATH_TRANSACTION: u32 = CALL_TRANSACTION + 14;
        const WRITE_FILE_DESCRIPTOR_TRANSACTION: u32 = CALL_TRANSACTION + 15;
        const WRITE_FILE_TRANSACTION: u32 = CALL_TRANSACTION + 16;
        const EXIT_TRANSACTION: u32 = CALL_TRANSACTION + 17;
        const DELAYED_EXIT_TRANSACTION: u32 = CALL_TRANSACTION + 18;
        const GET_PTR_SIZED_TRANSACTION: u32 = CALL_TRANSACTION + 19;
        const CREATE_BINDER_TRANSACTION: u32 = CALL_TRANSACTION + 20;
        const GET_WORK_SOURCE_TRANSACTION: u32 = CALL_TRANSACTION + 21;
        const ECHO_VECTOR: u32 = CALL_TRANSACTION + 22;

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
            SET_ERROR_TRANSACTION => Self::SetErrorTransaction,
            GET_STATUS_TRANSACTION => Self::GetStatusTransaction,
            ADD_STRONG_REF_TRANSACTION => Self::AddStrongRefTransaction,
            LINK_DEATH_TRANSACTION => Self::LinkDeathTransaction,
            WRITE_FILE_DESCRIPTOR_TRANSACTION => Self::WriteFileDescriptorTransaction,
            WRITE_FILE_TRANSACTION => Self::WriteFileTransaction,
            EXIT_TRANSACTION => Self::ExitTransaction,
            DELAYED_EXIT_TRANSACTION => Self::DelayedExitTransaction,
            GET_PTR_SIZED_TRANSACTION => Self::GetPtrSizeTransaction,
            CREATE_BINDER_TRANSACTION => Self::CreateBinderTransaction,
            GET_WORK_SOURCE_TRANSACTION => Self::GetWorkSourceTransaction,
            ECHO_VECTOR => Self::EchoVector,
            _ => return Err(BinderError::UNKNOWN_TRANSACTION),
        })
    }
}

#[derive(Debug)]
struct TestEnv<'s> {
    test_service_name: String,
    binder_server_suffix: &'s str,
    bin_path: &'s str,
}

struct Server<'s> {
    test_env: TestEnv<'s>,
    m_id: i32,
    m_next_server_id: AtomicI32,
    m_server_start_requested: Mutex<bool>,
    m_server_wait_cond: Condvar,
    m_server_started: Mutex<Option<Interface>>,
    m_callback: Mutex<Option<Interface>>,
    m_strong_ref: Mutex<Option<Interface>>,
}

impl<'s> Server<'s> {
    fn new(m_id: i32, test_env: TestEnv<'s>) -> Self {
        Server {
            test_env,
            m_id,
            m_next_server_id: AtomicI32::new(m_id + 1),
            m_server_start_requested: Mutex::new(false),
            m_server_wait_cond: Condvar::new(),
            m_server_started: Mutex::new(None),
            m_callback: Mutex::new(None),
            m_strong_ref: Mutex::new(None),
        }
    }

    fn run(mut self, _readpipefd: RawFd, use_poll: bool) -> Result<(), Box<dyn Error>> {
        self.test_env
            .test_service_name
            .push_str(self.test_env.binder_server_suffix);

        // This clone is avoidable with a little bit of work, if we want to remove it.
        let test_service_name = self.test_env.test_service_name.clone();
        let m_id = self.m_id;
        let mut sm = ServiceManager::default();
        let test_service_ptr;

        {
            let mut binder_native = Service::new(self);

            // Normally would also contain functionality as well, but we are only
            // testing the extension mechanism.
            binder_native.set_extension(&Service::new(()).into());

            // We can't hold a Sp<Service<Self>> or else it'll never drop
            // and decrement to 0. That would prevent the process from exiting
            // and continue to hang. So we have to take a raw ptr and let the Sp
            // drop. This should be safe because the ptr is only accessed in the
            // below loop and when the Sp does decrement to 0, the process will
            // exit via Server::drop. So this ptr cannot become invalid. This is
            // identical to how the original C++ test was written.
            test_service_ptr = binder_native.deref() as *const Self;

            if m_id == 0 {
                sm.add_service(
                    &test_service_name,
                    binder_native.into(),
                    false,
                    DumpFlags::PriorityDefault,
                )?;
            } else {
                let mut server = sm
                    .get_service(&test_service_name)
                    .ok_or(BinderError::NAME_NOT_FOUND)?;
                let mut data = Parcel::new();
                let mut reply = Parcel::new();

                data.write_i32(m_id)?;
                data.write_service(&binder_native)?;

                server.transact(RegisterServer as u32, &data, Some(&mut reply), 0)?;
            }
        }

        if use_poll {
            let fd = unsafe { ThreadState::setup_polling() };

            if fd < 0 {
                return Err("Failed to setup polling".into());
            }

            // flush BC_ENTER_LOOPER
            ThreadState::flush_commands();

            let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };

            if epoll_fd == -1 {
                return Err("Failed to get epoll fd".into());
            }

            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: 0,
            };

            if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev) } == -1 {
                return Err("Call to epoll_ctl failed".into());
            }

            loop {
                // We simulate a single-threaded process using the binder poll
                // interface; besides handling binder commands, it can also
                // issue outgoing transactions, by storing a callback in
                // m_callback.
                //
                // process_pending_call() will then issue that transaction.

                let mut event = libc::epoll_event { events: 0, u64: 0 };
                let num_events = unsafe { libc::epoll_wait(epoll_fd, &mut event, 1, 1000) };

                if num_events < 0 {
                    if unsafe { *libc::__errno() } == libc::EINTR {
                        continue;
                    }

                    return Err("Found unexpected errno value".into());
                } else if num_events > 0 {
                    let _ = unsafe { ThreadState::handle_polled_commands() };
                    ThreadState::flush_commands(); // flush BC_FREE_BUFFER

                    // Safety: See above test_service_ptr comment
                    unsafe {
                        (*test_service_ptr).process_pending_call();
                    }
                }
            }
        } else {
            ProcessState::start_thread_pool();
            ThreadState::join_thread_pool(true);
        }

        unreachable!("join_thread_pool should never return and polling will never reach this point")
    }

    fn process_pending_call(&self) {
        if let Some(mut m_callback) = self.m_callback.lock().unwrap().take() {
            let mut data = Parcel::new();

            let _ = data.write_i32(BinderError::OK as i32);
            let _ = m_callback.transact(Callback as u32, &data, None, Interface::FLAG_ONEWAY);
        }
    }
}

impl Binder for Server<'_> {
    const INTERFACE_DESCRIPTOR: &'static str = "test.binderLib";

    fn on_transact(
        &self,
        code: u32,
        data: &Parcel,
        reply: &mut Parcel,
        _flags: u32,
    ) -> BinderResult<()> {
        let uid = unsafe { libc::getuid() };
        let calling_uid = ThreadState::get_calling_uid();

        if uid != calling_uid {
            return Err(BinderError::PERMISSION_DENIED);
        }

        let code = TransactionCode::try_from(code)?;

        use TransactionCode::*;

        match code {
            RegisterServer => {
                let _id = data.read_i32();
                let binder = Interface::deserialize(&data).map_err(|_| BinderError::BAD_VALUE)?;

                if self.m_id != 0 {
                    return Err(BinderError::INVALID_OPERATION);
                }

                let mut server_start_requested = self.m_server_start_requested.lock().unwrap();

                if *server_start_requested {
                    *server_start_requested = false;
                    *self.m_server_started.lock().unwrap() = Some(binder);
                    self.m_server_wait_cond.notify_all();
                }
            }
            AddPollServer | AddServer => {
                let mut ret;
                let mut server_id = 0;
                let mut got_valid_pid = false;

                if self.m_id != 0 {
                    return Err(BinderError::INVALID_OPERATION);
                }

                let mut server_start_requested = self.m_server_start_requested.lock().unwrap();

                if *server_start_requested {
                    ret = Err(BinderError::INVALID_OPERATION);
                } else {
                    server_id = self.m_next_server_id.fetch_add(1, Ordering::SeqCst);

                    *server_start_requested = true;

                    let use_poll = code == AddPollServer;

                    drop(server_start_requested);
                    ret = start_server_process(server_id, &self.test_env, use_poll).map(|_| ());
                    server_start_requested = self.m_server_start_requested.lock().unwrap();
                    got_valid_pid = true;
                }

                if got_valid_pid {
                    if *server_start_requested {
                        let mut ts = get_clock_realtime();
                        ts.tv_sec += 5;

                        let dur = Duration::new(
                            ts.tv_sec.try_into().unwrap(),
                            ts.tv_nsec.try_into().unwrap(),
                        );

                        // This stores the return value into ret in the original. But this seems
                        // superfluous since it'll be overwritten in the following if/else?
                        let (lock, _) = self
                            .m_server_wait_cond
                            .wait_timeout(server_start_requested, dur)
                            .unwrap();

                        server_start_requested = lock;
                    }

                    if *server_start_requested {
                        *server_start_requested = false;
                        ret = Err(BinderError::TIMED_OUT);
                    } else {
                        let mut server_started = self.m_server_started.lock().unwrap();
                        server_started
                            .as_ref()
                            .expect("Server started")
                            .serialize(reply)?;
                        reply.write_i32(server_id)?;
                        *server_started = None;
                        ret = Ok(());
                    }
                } else if ret.is_ok() {
                    *server_start_requested = false;
                    ret = Err(BinderError::UNKNOWN_ERROR);
                }

                return ret;
            }
            NopTransaction => {}
            DelayedCallBack => {
                // Note: this transaction is only designed for use with a
                // poll() server. See comments around epoll_wait().

                let mut m_callback = self.m_callback.lock().unwrap();

                if let Some(ref mut _m_callback) = *m_callback {
                    // A callback was already pending; this means that
                    // we received a second call while still processing
                    // the first one. Fail the test.
                    let mut callback = Interface::deserialize(&data)?;
                    let mut data2 = Parcel::new();

                    data2.write_i32(BinderError::UNKNOWN_ERROR as i32)?;

                    callback.transact(Callback as u32, &data2, None, Interface::FLAG_ONEWAY)?;
                } else {
                    *m_callback = Some(Interface::deserialize(&data)?);

                    let delay_us = data.read_i32()?;

                    // It's necessary that we sleep here, so the next
                    // transaction the caller makes will be queued to
                    // the async queue.
                    sleep(Duration::from_micros(
                        delay_us.try_into().map_err(|_| BinderError::BAD_VALUE)?,
                    ));

                    // Now when we return, libbinder will tell the kernel
                    // we are done with this transaction, and the kernel
                    // can move the queued transaction to either the
                    // thread todo worklist (for kernels without the fix),
                    // or the proc todo worklist. In case of the former,
                    // the next outbound call will pick up the pending
                    // transaction, which leads to undesired reentrant
                    // behavior. This is caught in the if() branch above.
                }
            }
            NopCallback => {
                let mut data2 = Parcel::new();
                let mut reply2 = Parcel::new();
                let mut binder =
                    Interface::deserialize(&data).map_err(|_| BinderError::BAD_VALUE)?;

                data2.write_i32(0)?;
                binder.transact(Callback as u32, &data2, Some(&mut reply2), 0)?;
            }
            GetSelfTransaction => {
                // self.serialize(&mut reply); // Disregards error?
                unimplemented!()
            }
            GetIdTransaction => {
                reply.write_i32(self.m_id)?;
            }
            IndirectTransaction => {
                let count = data.read_i32()?;
                reply.write_i32(self.m_id)?;
                reply.write_i32(count)?;

                for _ in 0..count {
                    let mut binder = data
                        .read::<Interface>()
                        .map_err(|_| BinderError::BAD_VALUE)?;
                    let indirect_code = data.read_i32()?;
                    let data2 = TestBundle::new(&data)?;

                    if !data2.is_valid() {
                        return Err(BinderError::BAD_VALUE);
                    }

                    let mut reply2 = TestBundle::empty();

                    binder.transact(
                        indirect_code.try_into().unwrap(),
                        &data2,
                        Some(&mut reply2),
                        0,
                    )?;
                    reply2.append_to(reply)?;
                }
            }
            SetErrorTransaction => {
                reply.set_error(data.read_i32()?);
            }
            GetPtrSizeTransaction => {
                reply
                    .write_i32(size_of::<usize>().try_into().unwrap())?;
            }
            GetStatusTransaction => {}
            AddStrongRefTransaction => {
                *self.m_strong_ref.lock().unwrap() = Some(Interface::deserialize(&data)?);
            }
            LinkDeathTransaction => {
                let mut data2 = Parcel::new();
                let mut reply2 = Parcel::new();
                let death_recipient = DeathRecipient::new(TestDeathRecipient::new());
                let mut target = Interface::deserialize(&data)?;
                let mut callback = Interface::deserialize(&data)?;
                let ret = target.link_to_death(&death_recipient, None, 0);

                if ret.is_ok() {
                    death_recipient.wait_event(5)?;
                }

                data2.write_i32(ret.err().map(|e| e as i32).unwrap_or(0))?;
                callback.transact(Callback as u32, &data2, Some(&mut reply2), 0)?;
            }
            WriteFileDescriptorTransaction => {
                let fd = unsafe {
                    data.read_file_descriptor()
                        .map_err(|_| BinderError::BAD_VALUE)?
                };
                let size = data.read_i32()?;
                let buf = data.read_inplace(size.try_into().unwrap());

                if buf.is_empty() {
                    return Err(BinderError::BAD_VALUE);
                }

                // We don't want the fd to be closed on file drop as it is owned by `data` and will
                // be closed when `data` drops.
                let mut file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
                let result = file.write(buf);

                match result {
                    Ok(bytes_written) if bytes_written == size.try_into().unwrap() => {}
                    _ => return Err(BinderError::UNKNOWN_ERROR),
                }
            }
            WriteFileTransaction => {
                let mut file = data.read_file()?;
                let size = data.read_i32()?;
                let buf = data.read_inplace(size.try_into().unwrap());

                if buf.is_empty() {
                    return Err(BinderError::BAD_VALUE);
                }

                let result = file.write(buf);

                file.flush().unwrap();

                match result {
                    Ok(bytes_written) if bytes_written == size.try_into().unwrap() => {}
                    _ => return Err(BinderError::UNKNOWN_ERROR),
                }
            }
            DelayedExitTransaction => {
                unsafe { libc::alarm(10) };
            }
            ExitTransaction => {
                while unsafe {
                    libc::wait(ptr::null_mut()) != -1 || *libc::__errno() != libc::ECHILD
                } {}

                exit(0);
            }
            CreateBinderTransaction => {
                let binder = Service::new(());
                reply.write_service(&binder)?;
            }
            GetWorkSourceTransaction => unsafe {
                data.enforce_interface(&(&*self.test_env.test_service_name).into());
                reply.write_i32(ThreadState::get_calling_work_source_uid() as i32)?;
            },
            EchoVector => {
                let vector = data.read::<[u64]>()?;
                reply.write_slice(&vector)?;
            }
            Callback | CallbackVerifyBuf => {
                return Err(BinderError::UNKNOWN_ERROR);
            }
        }

        Ok(())
    }
}

impl Drop for Server<'_> {
    fn drop(&mut self) {
        exit(0);
    }
}

struct TestDeathRecipient(TestEvent);

impl TestDeathRecipient {
    fn new() -> Self {
        TestDeathRecipient(TestEvent::new())
    }
}

impl DeathRecipientCallback for TestDeathRecipient {
    fn binder_died(&self, _weak_interface: &WeakInterface) {
        self.0.trigger_event();

        // REVIEW: Sometimes promotes, sometimes not in a non-deterministic fashion.
        // There seems to be a chance of a sp lingering when binder_died is called.
        // The same appears be true of the original test, though.
        // if let Ok(strong_ref) = weak_interface.promote() {
        //     panic!("Found {} strong refs, expected 0.", strong_ref.strong_count());
        // }
    }
}

impl TestDeathRecipient {
    fn wait_event(&self, timeout_s: libc::c_int) -> BinderResult<()> {
        self.0.wait_event(timeout_s)
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
    Error(BinderError),
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

        match self.kind {
            TestErrorKind::Assert => write!(f, "test_assert!({})", self.src),
            TestErrorKind::Error(e) => write!(f, "{} == {}", self.src, e),
            TestErrorKind::Unimplemented => f.write_str(self.src),
        }
    }
}

impl From<BinderError> for TestErrorKind {
    fn from(e: BinderError) -> Self {
        TestErrorKind::Error(e)
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

// TODO: Opt params like regular assert
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

// TODO: Opt params like regular assert
/// Like the `assert_eq!` macro but fails a test rather than `panic!`-ing.
macro_rules! test_assert_eq {
    ($lhs:expr, $rhs:expr) => {
        test_assert!($lhs == $rhs)
    };
}

macro_rules! count_tokens {
    () => (0);
    ( $x:tt $($xs:tt)* ) => (1 + count_tokens!($($xs)*));
}

type TestResult = Result<(), TestError>;

struct Test<'s> {
    method: fn(&mut Client<'s>) -> TestResult,
    test_name: &'static str,
    skipped: bool,
}

struct Client<'s> {
    test_env: TestEnv<'s>,
    m_server: Interface,
    server_process: Child,
    tests: Vec<Test<'s>>,
}

impl<'s> Client<'s> {
    fn try_new(test_env: TestEnv<'s>) -> BinderResult<Self> {
        let server_process = start_server_process(0, &test_env, false)?;
        let m_server = ServiceManager::default()
            .get_service(&test_env.test_service_name)
            .ok_or(BinderError::NAME_NOT_FOUND)?;

        macro_rules! tests {
            ($($test_name:ident $(: $modifier:ident)?,)+) => {{
                let mut tests = Vec::with_capacity(count_tokens!($($test_name)+));

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

        // The CheckHandleZeroBinderHighBitsZeroCookie and FreedBinder tests were not
        // ported over because they involve flat_binder_object manipulation, which
        // is not part of the public API.

        let tests = tests! {
            test_nop_transaction,
            test_set_error,
            test_get_id,
            test_ptr_size,
            test_indirect_get_id2,
            test_indirect_get_id3,
            test_callback,
            test_add_server,
            test_death_notification_multiple,
            test_death_notification_strong_ref,
            test_death_notification_thread,
            test_pass_file_descriptor,
            test_pass_file,
            test_promote_local,
            test_local_get_extension,
            test_remote_get_extension,
            test_check_no_header_mapped_in_user,
            test_oneway_queueing,
            test_work_source_unset_by_default,
            test_work_source_set,
            test_work_source_set_without_propagation,
            test_work_source_cleared,
            test_work_source_restored,
            test_propagate_flag_set,
            test_propagate_flag_cleared,
            test_propagate_flag_restored,
            test_work_source_propagated_for_all_following_binder_calls,
            test_vector_sent,
        };

        Ok(Client {
            test_env,
            m_server,
            server_process,
            tests,
        })
    }

    fn run_all_tests(mut self) -> Vec<TestOutcome> {
        let mut outcomes = Vec::with_capacity(self.tests.len());
        let tests = replace(&mut self.tests, Vec::new());

        for test in tests {
            let status = if test.skipped {
                TestStatus::Skipped
            } else {
                self.setup_test();

                match (test.method)(&mut self) {
                    Ok(()) => TestStatus::Passed,
                    Err(e) => TestStatus::Failed(e),
                }
            };

            outcomes.push(TestOutcome { status, test_name: test.test_name });
        }

        outcomes
    }

    fn setup_test(&self) {
        unsafe {
            ThreadState::restore_calling_work_source(0);
        }
    }

    fn add_server(&mut self, is_poll: bool) -> BinderResult<(Interface, i32)> {
        let data = Parcel::new();
        let mut reply = Parcel::new();
        let code = if is_poll { AddPollServer } else { AddServer } as u32;

        self.m_server.transact(code, &data, Some(&mut reply), 0)?;

        let binder = reply.read::<Interface>()?;
        let id = reply.read_i32()?;

        return Ok((binder, id));
    }

    fn test_promote_local(&mut self) -> TestResult {
        let strong = Service::new(());
        let weak = strong.demote();
        let strong_from_weak = test_try!(weak.promote());

        test_assert_eq!(strong, strong_from_weak);

        drop(strong);
        drop(strong_from_weak);

        test_assert!(weak.promote().is_err());

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
        let mut linked_clients = Vec::with_capacity(CLIENT_COUNT);
        let mut passive_clients = Vec::with_capacity(CLIENT_COUNT);
        let mut target = test_try!(self.add_server(false)).0;

        for i in 0..CLIENT_COUNT {
            {
                let mut data = Parcel::new();
                let mut reply = Parcel::new();

                linked_clients.push(test_try!(self.add_server(false)).0);
                callbacks.push(Service::new(TestCallback::new(None)));

                test_try!(data.write(&target));
                test_try!(data.write_service(&callbacks[i]));
                test_try!(linked_clients[i].transact(
                    LinkDeathTransaction as u32,
                    &data,
                    Some(&mut reply),
                    Interface::FLAG_ONEWAY
                ));
            }
            {
                let mut data = Parcel::new();
                let mut reply = Parcel::new();

                passive_clients.push(test_try!(self.add_server(false)).0);

                test_try!(data.write(&target));
                test_try!(passive_clients[i].transact(
                    AddStrongRefTransaction as u32,
                    &data,
                    Some(&mut reply),
                    Interface::FLAG_ONEWAY
                ));
            }
        }
        {
            let data = Parcel::new();
            let mut reply = Parcel::new();

            test_try!(target.transact(
                ExitTransaction as u32,
                &data,
                Some(&mut reply),
                Interface::FLAG_ONEWAY
            ));
        }

        for i in 0..CLIENT_COUNT {
            test_try!(callbacks[i].wait_event(5));
            test_try!(callbacks[i].get_result());
        }

        Ok(())
    }

    fn test_death_notification_strong_ref(&mut self) -> TestResult {
        let death_recipient = DeathRecipient::new(TestDeathRecipient::new());

        let mut sbinder = {
            let mut binder = test_try!(self.add_server(false)).0;

            test_try!(binder.link_to_death(&death_recipient, None, 0));
            binder.clone()
        };
        {
            let data = Parcel::new();
            let mut reply = Parcel::new();

            test_try!(sbinder.transact(
                ExitTransaction as u32,
                &data,
                Some(&mut reply),
                Interface::FLAG_ONEWAY
            ));
        }

        ThreadState::flush_commands();

        test_try!(death_recipient.wait_event(5));
        test_assert_eq!(
            sbinder.unlink_to_death(&death_recipient.demote(), None, 0),
            Err(BinderError::DEAD_OBJECT)
        );

        Ok(())
    }

    fn test_death_notification_thread(&mut self) -> TestResult {
        let callback;
        let mut target = test_try!(self.add_server(false)).0;
        let mut client = test_try!(self.add_server(false)).0;
        let death_recipient = DeathRecipient::new(TestDeathRecipient::new());

        test_try!(target.link_to_death(&death_recipient, None, 0));

        {
            let data = Parcel::new();
            let mut reply = Parcel::new();

            test_try!(target.transact(
                ExitTransaction as u32,
                &data,
                Some(&mut reply),
                Interface::FLAG_ONEWAY
            ));
        }

        // Make sure it's dead
        test_try!(death_recipient.wait_event(5));

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
            let mut data = Parcel::new();
            let mut reply = Parcel::new();

            callback = Service::new(TestCallback::new(None));

            test_try!(data.write(&target));
            test_try!(data.write_service(&callback));
            test_try!(client.transact(
                LinkDeathTransaction as u32,
                &data,
                Some(&mut reply),
                Interface::FLAG_ONEWAY
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
            let mut data = Parcel::new();
            let mut reply = Parcel::new();
            let write_buf = [write_value];

            unsafe {
                test_try!(data.write_file_descriptor(pipe_fds[1], true));
            }

            test_try!(data.write_slice(&write_buf));

            test_try!(self.m_server.transact(
                WriteFileDescriptorTransaction as u32,
                &data,
                Some(&mut reply),
                0
            ));
        }

        let mut file = unsafe { File::from_raw_fd(pipe_fds[0]) };

        let bytes_written = file.read(&mut buf).expect("to write to pipe");

        test_assert_eq!(bytes_written, size_of_val(&buf));
        test_assert_eq!(write_value, buf[0]);

        // Wait for other process to close pipe:
        self.wait_for_read_data(pipe_fds[0], 5000)?;

        let bytes_written = file.read(&mut buf).expect("to write to pipe");

        test_assert_eq!(bytes_written, 0);

        unsafe {
            libc::close(pipe_fds[0]);
        }

        Ok(())
    }

    fn test_pass_file(&mut self) -> TestResult {
        const DATA_SIZE: u8 = 123;

        let write_buf: Vec<_> = (0..DATA_SIZE).collect();

        let (mut read_end, write_end) = {
            let mut pipe_fds: [RawFd; 2] = [0, 0];
            let ret = unsafe { pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK) };

            test_assert_eq!(ret, 0);

            unsafe {
                (
                    File::from_raw_fd(pipe_fds[0]),
                    File::from_raw_fd(pipe_fds[1]),
                )
            }
        };

        {
            let mut data = Parcel::new();

            test_try!(data.write_file(write_end));

            test_try!(data.write_slice(&write_buf));

            let mut reply = Parcel::new();

            test_try!(self.m_server.transact(
                WriteFileTransaction as u32,
                &data,
                Some(&mut reply),
                0
            ));
        }

        let mut read_buf: Vec<_> = (0..DATA_SIZE).collect();
        let bytes_written = read_end.read(&mut read_buf).expect("to write to pipe");

        test_assert_eq!(bytes_written, DATA_SIZE as usize);
        test_assert_eq!(write_buf, read_buf);

        // Wait for other process to close pipe:
        self.wait_for_read_data(read_end.as_raw_fd(), 5000)?;

        let bytes_written = read_end.read(&mut read_buf).expect("to write to pipe");

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

    fn test_set_error(&mut self) -> TestResult {
        let test_value = [0, -123, 123];

        for i in 0..test_value.len() {
            let mut data = Parcel::new();
            let mut reply = Parcel::new();

            test_try!(data.write_i32(test_value[i]));

            // Return enum won't make sense (ok, unknown, unknown) so we need to
            // check error_check instead to be equivalent to the original test
            let _ = self
                .m_server
                .transact(SetErrorTransaction as u32, &data, Some(&mut reply), 0);

            test_assert_eq!(reply.error_check(), test_value[i]);
        }

        Ok(())
    }

    fn test_callback(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();
        let callback = Service::new(TestCallback::new(None));

        test_try!(data.write_service(&callback));
        test_try!(self.m_server.transact(
            NopCallback as u32,
            &data,
            Some(&mut reply),
            Interface::FLAG_ONEWAY,
        ));

        test_try!(callback.wait_event(5));
        test_try!(callback.get_result());

        Ok(())
    }

    fn test_local_get_extension(&mut self) -> TestResult {
        let mut binder = Service::new(());
        let ext = Service::new(()).into();

        test_assert!(binder.get_extension().unwrap().is_none());

        binder.set_extension(&ext);

        test_assert_eq!(binder.get_extension().unwrap(), Some(ext));

        Ok(())
    }

    fn test_check_no_header_mapped_in_user(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();
        let callback = Service::new(TestCallback::new(Some(self.m_server.clone())));

        for _ in 0..2 {
            let mut datai = TestBundle::empty();

            test_try!(datai.append_from(&data, 0, data.data_size()));

            data.free_data();

            test_try!(data.write_i32(1));
            test_try!(data.write_service(&callback));
            test_try!(data.write_i32(CallbackVerifyBuf as i32));
            test_try!(datai.append_to(&mut data));
        }

        test_try!(self
            .m_server
            .transact(IndirectTransaction as u32, &data, Some(&mut reply), 0));

        Ok(())
    }

    fn test_oneway_queueing(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut data2 = Parcel::new();
        let (mut poll_server, _id) = test_try!(self.add_server(true));
        let callback = Service::new(TestCallback::new(None));

        test_try!(data.write_service(&callback));
        test_try!(data.write_i32(500000)); // delay in us before calling back

        let callback2 = Service::new(TestCallback::new(None));

        test_try!(data2.write_service(&callback2));
        test_try!(data2.write_i32(0)); // delay in us

        test_try!(poll_server.transact(
            DelayedCallBack as u32,
            &data,
            None,
            Interface::FLAG_ONEWAY
        ));

        // The delay ensures that this second transaction will end up on the async_todo list
        // (for a single-threaded server)
        test_try!(poll_server.transact(
            DelayedCallBack as u32,
            &data2,
            None,
            Interface::FLAG_ONEWAY
        ));

        // The server will ensure that the two transactions are handled in the expected order;
        // If the ordering is not as expected, an error will be returned through the callbacks.
        test_try!(callback.wait_event(2));
        test_try!(callback.get_result());
        test_try!(callback2.wait_event(2));
        test_try!(callback2.get_result());

        Ok(())
    }

    fn test_work_source_restored(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();

        unsafe {
            ThreadState::set_calling_work_source_uid(100);
            let token = ThreadState::clear_calling_work_source();
            ThreadState::restore_calling_work_source(token);

            test_try!(data.write_interface_token(&(&*self.test_env.test_service_name).into()));
            test_try!(self.m_server.transact(
                GetWorkSourceTransaction as u32,
                &data,
                Some(&mut reply),
                0
            ));

            test_assert_eq!(reply.read_i32(), Ok(100));
            test_assert!(ThreadState::should_propagate_work_source());
        }

        Ok(())
    }

    fn test_work_source_set_without_propagation(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();

        unsafe {
            ThreadState::set_calling_work_source_uid_without_propagation(100);
            assert!(!ThreadState::should_propagate_work_source());

            test_try!(data.write_interface_token(&(&*self.test_env.test_service_name).into()));
            test_try!(self.m_server.transact(
                GetWorkSourceTransaction as u32,
                &data,
                Some(&mut reply),
                0
            ));

            test_assert_eq!(reply.read_i32(), Ok(-1));
            test_assert!(!ThreadState::should_propagate_work_source());
        }

        Ok(())
    }

    fn test_work_source_propagated_for_all_following_binder_calls(
        &mut self,
    ) -> TestResult {
        unsafe {
            ThreadState::set_calling_work_source_uid(100);
        }

        let mut data = Parcel::new();
        let mut reply = Parcel::new();

        unsafe {
            test_try!(data.write_interface_token(&(&*self.test_env.test_service_name).into()));
        }

        test_try!(self.m_server.transact(
            GetWorkSourceTransaction as u32,
            &data,
            Some(&mut reply),
            0
        ));

        let mut data2 = Parcel::new();
        let mut reply2 = Parcel::new();

        unsafe {
            test_try!(data2.write_interface_token(&(&*self.test_env.test_service_name).into()));
        }

        test_try!(self.m_server.transact(
            GetWorkSourceTransaction as u32,
            &data2,
            Some(&mut reply2),
            0
        ));

        test_assert_eq!(reply2.read_i32(), Ok(100));

        Ok(())
    }

    fn test_work_source_set(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();

        unsafe {
            ThreadState::clear_calling_work_source();
            let previous_work_source = ThreadState::set_calling_work_source_uid(100);

            test_try!(data.write_interface_token(&(&*self.test_env.test_service_name).into()));
            test_try!(self.m_server.transact(
                GetWorkSourceTransaction as u32,
                &data,
                Some(&mut reply),
                0
            ));

            test_assert_eq!(reply.read_i32(), Ok(100));
            test_assert_eq!(previous_work_source, -1);
            test_assert!(ThreadState::should_propagate_work_source());
        }

        Ok(())
    }

    fn test_work_source_cleared(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();

        unsafe {
            ThreadState::set_calling_work_source_uid(100);
            let token = ThreadState::clear_calling_work_source();
            let previous_work_source = token as i32;

            test_try!(data.write_interface_token(&(&*self.test_env.test_service_name).into()));
            test_try!(self.m_server.transact(
                GetWorkSourceTransaction as u32,
                &data,
                Some(&mut reply),
                0
            ));

            test_assert_eq!(reply.read_i32(), Ok(-1));
            test_assert_eq!(previous_work_source, 100);
        }

        Ok(())
    }

    fn test_work_source_unset_by_default(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();

        // TODO: impl From<String> for String16?
        unsafe {
            test_try!(data.write_interface_token(&(&*self.test_env.test_service_name).into()));
        }
        test_try!(self.m_server.transact(
            GetWorkSourceTransaction as u32,
            &data,
            Some(&mut reply),
            0
        ));

        test_assert_eq!(reply.read_i32(), Ok(-1));

        Ok(())
    }

    fn test_propagate_flag_set(&mut self) -> TestResult {
        unsafe {
            ThreadState::clear_propagate_work_source();
            ThreadState::set_calling_work_source_uid(100);

            test_assert!(ThreadState::should_propagate_work_source());
        }

        Ok(())
    }

    fn test_propagate_flag_cleared(&mut self) -> TestResult {
        unsafe {
            ThreadState::set_calling_work_source_uid(100);
            ThreadState::clear_propagate_work_source();

            test_assert!(!ThreadState::should_propagate_work_source());
        }

        Ok(())
    }

    fn test_propagate_flag_restored(&mut self) -> TestResult {
        unsafe {
            let token = ThreadState::set_calling_work_source_uid(100);

            ThreadState::restore_calling_work_source(token);

            test_assert!(!ThreadState::should_propagate_work_source());
        }

        Ok(())
    }

    fn test_nop_transaction(&mut self) -> TestResult {
        let data = Parcel::new();
        let mut reply = Parcel::new();

        test_try!(self
            .m_server
            .transact(NopTransaction as u32, &data, Some(&mut reply), 0));

        Ok(())
    }

    fn test_get_id(&mut self) -> TestResult {
        let data = Parcel::new();
        let mut reply = Parcel::new();

        test_try!(self
            .m_server
            .transact(GetIdTransaction as u32, &data, Some(&mut reply), 0));

        test_assert_eq!(test_try!(reply.read_i32()), 0);

        Ok(())
    }
    fn test_ptr_size(&mut self) -> TestResult {
        let data = Parcel::new();
        let mut reply = Parcel::new();
        let (mut server, _id) = test_try!(self.add_server(false));

        test_try!(server.transact(GetPtrSizeTransaction as u32, &data, Some(&mut reply), 0));

        let ptr_size = test_try!(reply.read_i32());

        test_assert_eq!(ptr_size as usize, size_of::<usize>());

        // TODO: What are these for?
        // RecordProperty("TestPtrSize", sizeof(void *));
        // RecordProperty("ServerPtrSize", sizeof(void *));

        Ok(())
    }

    fn test_indirect_get_id2(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();
        let mut server_ids = [0, 0, 0];

        test_try!(data.write_i32(server_ids.len() as i32));

        for i in 0..server_ids.len() {
            let (server, id) = test_try!(self.add_server(false));

            server_ids[i] = id;

            test_try!(data.write(&server));
            test_try!(data.write_i32(GetIdTransaction as i32));
            test_try!(TestBundle::empty().append_to(&mut data));
        }

        test_try!(self
            .m_server
            .transact(IndirectTransaction as u32, &data, Some(&mut reply), 0));

        let id = test_try!(reply.read_i32());

        test_assert_eq!(id, 0);

        let count = test_try!(reply.read_i32());

        test_assert_eq!(server_ids.len(), count.try_into().unwrap());

        Ok(())
    }

    fn test_indirect_get_id3(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();
        let mut server_ids = [0, 0, 0];

        test_try!(data.write_i32(server_ids.len() as i32));

        for i in 0..server_ids.len() {
            let (server, id) = test_try!(self.add_server(false));

            server_ids[i] = id;

            let mut datai = TestBundle::empty();
            let datai2 = TestBundle::empty();

            test_try!(data.write(&server));
            test_try!(data.write_i32(IndirectTransaction as i32));
            test_try!(datai.write_i32(1));
            test_try!(datai.write(&self.m_server));
            test_try!(datai.write_i32(GetIdTransaction as i32));
            test_try!(datai2.append_to(&mut datai));
            test_try!(datai.append_to(&mut data));
        }

        test_try!(self
            .m_server
            .transact(IndirectTransaction as u32, &data, Some(&mut reply), 0));

        let id = test_try!(reply.read_i32());

        test_assert_eq!(id, 0);

        let count = test_try!(reply.read_i32());

        test_assert_eq!(count, server_ids.len() as i32);

        for i in 0..count {
            let replyi = test_try!(TestBundle::new(&reply));

            test_assert!(replyi.is_valid());

            let id = test_try!(replyi.read_i32());

            test_assert_eq!(id, server_ids[i as usize]);

            let counti = test_try!(replyi.read_i32());

            test_assert_eq!(counti, 1);

            let replyi2 = test_try!(TestBundle::new(&replyi));

            test_assert!(replyi2.is_valid());

            let id = test_try!(replyi2.read_i32());

            test_assert_eq!(id, 0);
            test_assert_eq!(replyi2.data_size(), replyi2.data_position());
            test_assert_eq!(replyi.data_size(), replyi.data_position());
        }

        test_assert_eq!(reply.data_size(), reply.data_position());

        Ok(())
    }

    fn test_add_server(&mut self) -> TestResult {
        test_try!(self.add_server(false).map(|_| ()));

        Ok(())
    }

    fn test_vector_sent(&mut self) -> TestResult {
        let mut data = Parcel::new();
        let mut reply = Parcel::new();
        let (mut server, _id) = test_try!(self.add_server(false));
        let test_value = [u64::max_value(), 0, 200];

        test_try!(data.write_slice(&test_value));
        test_try!(server.transact(EchoVector as u32, &data, Some(&mut reply), 0));

        let read_value = test_try!(<[u64]>::deserialize(&reply));

        test_assert_eq!(read_value, test_value);

        Ok(())
    }
}

impl Drop for Client<'_> {
    fn drop(&mut self) {
        let data = Parcel::new();
        let interface = &mut self.m_server;

        assert_eq!(
            interface.transact(GetStatusTransaction as u32, &data, None, 0),
            Ok(())
        );
        assert!(interface
            .transact(ExitTransaction as u32, &data, None, Interface::FLAG_ONEWAY)
            .is_ok());

        let mut exit_status = 0;
        let pid = unsafe { libc::wait(&mut exit_status) };

        assert_eq!(pid, self.server_process.id().try_into().unwrap());

        unsafe {
            assert!(libc::WIFEXITED(exit_status));
            assert_eq!(libc::WEXITSTATUS(exit_status), 0);
        }
    }
}

struct TestBundle {
    parcel: Parcel,
    is_valid: bool,
}

impl std::fmt::Debug for TestBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "TestBundle")
    }
}

impl TestBundle {
    const MARK_START: &'static [u8; 4] = b"BTBS";
    const MARK_END: &'static [u8; 4] = b"BTBE";

    fn new(source: &Parcel) -> BinderResult<Self> {
        let mark = source.read_i32()?;

        if mark != i32::from_ne_bytes(*Self::MARK_START) {
            return Err(BinderError::BAD_VALUE);
        }

        let bundle_len = source.read_i32()? as libc::c_ulong;
        let pos = source.data_position();
        let mut bundle = TestBundle::empty();

        bundle.parcel.append_from(&source, pos, bundle_len)?;

        source.set_data_position(pos + bundle_len)?;

        let mark = source.read_i32()?;

        if mark != i32::from_ne_bytes(*Self::MARK_END) {
            return Err(BinderError::BAD_VALUE);
        }

        bundle.is_valid = true;
        bundle.parcel.set_data_position(0)?;

        Ok(bundle)
    }

    fn empty() -> Self {
        TestBundle {
            parcel: Parcel::new(),
            is_valid: false,
        }
    }

    fn append_to(&self, dest: &mut Parcel) -> BinderResult<()> {
        dest.write_i32(i32::from_ne_bytes(*Self::MARK_START))?;
        dest.write_i32(self.parcel.data_size() as i32)?;
        dest.append_from(&self.parcel, 0, self.parcel.data_size())?;
        dest.write_i32(i32::from_ne_bytes(*Self::MARK_END))
    }

    fn is_valid(&self) -> bool {
        self.is_valid
    }
}

impl Deref for TestBundle {
    type Target = Parcel;

    fn deref(&self) -> &Self::Target {
        &self.parcel
    }
}

impl DerefMut for TestBundle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parcel
    }
}

struct TestCallback {
    test_event: TestEvent,
    m_result: Mutex<BinderResult<()>>,
    m_prev_end: Mutex<TestBufEnd>,
    m_server: Mutex<Option<Interface>>,
}

struct TestBufEnd(*const u8);

/// # Safety
///
/// We are using this pointer to mark the position of the shared parcel
/// buffer. We never derefence the pointer so it will not result in any thread
/// unsafety.
unsafe impl Send for TestBufEnd {}

impl TestCallback {
    fn new(m_server: Option<Interface>) -> Self {
        TestCallback {
            test_event: TestEvent::new(),
            m_result: Mutex::new(Err(BinderError::NOT_ENOUGH_DATA)),
            m_prev_end: Mutex::new(TestBufEnd(ptr::null())),
            m_server: Mutex::new(m_server),
        }
    }

    fn get_result(&self) -> BinderResult<()> {
        *self.m_result.lock().unwrap()
    }

    fn wait_event(&self, timeout_s: libc::c_int) -> BinderResult<()> {
        self.test_event.wait_event(timeout_s)
    }

    fn trigger_event(&self) {
        self.test_event.trigger_event()
    }
}

impl Binder for TestCallback {
    const INTERFACE_DESCRIPTOR: &'static str = "test.binderTestCallback";

    fn on_transact(
        &self,
        code: u32,
        data: &Parcel,
        reply: &mut Parcel,
        _flags: u32,
    ) -> BinderResult<()> {
        let code = TransactionCode::try_from(code);

        match code {
            Ok(Callback) => {
                *self.m_result.lock().unwrap() = data.read_i32().and_then(binder_status);
                self.trigger_event();

                Ok(())
            }
            Ok(CallbackVerifyBuf) => {
                let buf = data.data();

                {
                    let prev_end = &mut self.m_prev_end.lock().unwrap().0;

                    if !prev_end.is_null() {
                        // 64-bit kernel needs at most 8 bytes to align buffer end
                        assert!(wrapping_offset_from(buf.as_ptr(), *prev_end) <= 8);
                    } else {
                        assert!(is_page_aligned(buf.as_ptr()))
                    }

                    *prev_end = buf
                        .as_ptr()
                        .wrapping_add(buf.len())
                        .wrapping_add(data.objects_count().try_into().unwrap())
                        .wrapping_add(size_of::<binder::size_t>());
                }

                if buf.len() > 0 {
                    self.m_server.lock().unwrap().as_mut().unwrap().transact(
                        IndirectTransaction as u32,
                        &data,
                        Some(reply),
                        0,
                    )?;
                }

                Ok(())
            }
            _ => Err(BinderError::UNKNOWN_TRANSACTION),
        }
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

    fn wait_event(&self, timeout_s: libc::c_int) -> BinderResult<()> {
        let mut m_event_triggered = self.m_event_triggered.lock().unwrap();

        if !*m_event_triggered {
            let mut ts = get_clock_realtime();

            ts.tv_sec += libc::time_t::try_from(timeout_s).unwrap();

            let dur = Duration::new(
                ts.tv_sec.try_into().unwrap(),
                ts.tv_nsec.try_into().unwrap(),
            );

            // This stores the return value into ret in the original. But this seems
            // superfluous since it'll be overwritten in the following if/else?
            let (lock, _) = self
                .m_wait_cond
                .wait_timeout(m_event_triggered, dur)
                .unwrap();

            m_event_triggered = lock;
        }

        if *m_event_triggered {
            Ok(())
        } else {
            Err(BinderError::TIMED_OUT)
        }
    }

    fn trigger_event(&self) {
        let mut m_event_triggered = self.m_event_triggered.lock().unwrap();

        self.m_wait_cond.notify_all();

        *m_event_triggered = true;

        // TODO:
        // self.m_triggeringThread = pthread_self();
    }
}

// TODO: cfg other architectures?
const PAGE_SIZE: usize = 4096;

fn is_page_aligned<T>(buf: *const T) -> bool {
    ((buf as usize) & (PAGE_SIZE - 1)) == 0
}

// TODO: The following was taken from std but is currently nightly only. It can be
// swapped out once it is stabilized.
#[inline]
pub fn wrapping_offset_from<T: Sized>(end: *const T, origin: *const T) -> isize {
    let pointee_size = size_of::<T>();
    assert!(0 < pointee_size && pointee_size <= isize::max_value() as usize);

    let d = isize::wrapping_sub(end as _, origin as _);
    d.wrapping_div(pointee_size as _)
}

fn bytes_written(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len())
}

// REVIEW: Is there a safe rust equivalent of this?
fn get_clock_realtime() -> libc::timespec {
    let mut ts = MaybeUninit::uninit();
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, ts.as_mut_ptr());
        ts.assume_init()
    }
}

fn start_server_process(index: i32, test_env: &TestEnv, use_poll: bool) -> BinderResult<Child> {
    let mut index_bytes = [0u8; 11];

    write!(&mut index_bytes as &mut [u8], "{}", index).expect("i32 to always fit in 11 bytes");

    let bytes_written = bytes_written(&index_bytes);
    let index_str = str::from_utf8(&index_bytes[..bytes_written]).unwrap();
    let use_poll_str = if use_poll { "true" } else { "false" };
    let child = Command::new(test_env.bin_path)
        .arg("--binderserver")
        .arg(index_str)
        .arg("strpipefd1") // FIXME
        .arg(use_poll_str)
        .arg(test_env.binder_server_suffix)
        .spawn()
        .map_err(|_| BinderError::DEAD_OBJECT)?; // REVIEW: Not sure if best error kind here

    Ok(child)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = args();
    let bin_path = args.next().expect("Path arg should exist");
    let mut binder_server_suffix = [0u8; 16];
    let mut env = TestEnv {
        test_service_name: String::from("test.binderLib"),
        binder_server_suffix: "",
        bin_path: &bin_path,
    };
    let first_arg = args.next();

    if let Some("--binderserver") = first_arg.as_deref() {
        let args = (args.next(), args.next(), args.next(), args.next());

        if let (Some(index), Some(_strpipefd1), Some(use_poll), Some(server_suffix)) = args {
            let index = index.parse().expect("To find a valid id");
            let use_poll = use_poll == "true";

            env.binder_server_suffix = &server_suffix;

            return Server::new(index, env).run(0, use_poll);
        }
    }

    write!(&mut binder_server_suffix as &mut [u8], "{}", process::id())?;

    // Trimming the end of the slice so null bytes aren't appended.
    let first_zero = bytes_written(&binder_server_suffix);

    env.binder_server_suffix = str::from_utf8(&binder_server_suffix[..first_zero])?;
    env.test_service_name.push_str(env.binder_server_suffix);

    ProcessState::start_thread_pool();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    let client = Client::try_new(env)?;

    // Display the test count so that the trade federation can parse it.
    if let Some("--list") = first_arg.as_deref() {
        println!("{} tests, 0 benchmarks", client.tests.len());

        return Ok(())
    }

    for test_outcome in client.run_all_tests() {
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
    }.join("");

    println!(
        "\ntest result: {}. {} passed; {} failed; {} ignored;",
        status, passed, failed, skipped
    );

    Ok(())
}
