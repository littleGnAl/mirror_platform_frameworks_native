//! ShellCallback interface.

use crate::binder::{IBinder, TransactionCode, TransactionFlags};
use crate::parcel::Parcel;
use crate::proxy::Handle;
use crate::{Binder, Error, Interface, Result};

use std::fs::File;
use std::path::Path;
use std::sync::Mutex;

declare_binder_interface!(BpShellCallback: IShellCallback);

const OPEN_OUTPUT_FILE_TRANSACTION: TransactionCode = Interface::FIRST_CALL_TRANSACTION;

pub trait IShellCallback {
    const INTERFACE_DESCRIPTOR: &'static str = "com.android.internal.app.IShellCallback";

    fn open_file(&mut self, path: &Path, selinux_context: &str, mode: &str) -> Result<File>;
}

impl IShellCallback for BpShellCallback {
    fn open_file(&mut self, path: &Path, selinux_context: &str, mode: &str) -> Result<File> {
        let utf8_path = path.to_str().ok_or(Error::BAD_VALUE)?;
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&Self::INTERFACE_DESCRIPTOR.into())?;
        }
        data.write_utf8_as_utf16(utf8_path)?;
        data.write_utf8_as_utf16(selinux_context)?;
        data.write_utf8_as_utf16(mode)?;

        let mut reply = Parcel::new();
        self.remote_mut()
            .transact(OPEN_OUTPUT_FILE_TRANSACTION, &data, Some(&mut reply), 0)?;
        let _ = reply.read_exception_code();
        reply.read_file()
    }
}

pub struct ShellCallback<T: IShellCallback + Send>(Mutex<T>);

pub struct ShellCallbackClosure(Box<dyn Fn(&Path, &str, &str) -> Option<File> + Send + 'static>);

impl IShellCallback for ShellCallbackClosure {
    fn open_file(&mut self, path: &Path, selinux_context: &str, mode: &str) -> Result<File> {
        self.0(path, selinux_context, mode).ok_or(Error::BAD_VALUE)
    }
}

impl<T: IShellCallback + Send> IShellCallback for ShellCallback<T> {
    fn open_file(&mut self, path: &Path, selinux_context: &str, mode: &str) -> Result<File> {
        // If another thread panicked while holding the mutex we cannot access
        // it.
        self.0
            .get_mut()
            .or(Err(Error::DEAD_OBJECT))?
            .open_file(path, selinux_context, mode)
    }
}

impl ShellCallback<ShellCallbackClosure> {
    pub fn new<C>(callback: C) -> Self
    where
        C: Fn(&Path, &str, &str) -> Option<File> + Send + 'static,
    {
        ShellCallback(Mutex::new(ShellCallbackClosure(Box::new(callback))))
    }
}

impl<T: IShellCallback + Send> Binder for ShellCallback<T> {
    const INTERFACE_DESCRIPTOR: &'static str = <Self as IShellCallback>::INTERFACE_DESCRIPTOR;

    fn on_transact(
        &self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        _flags: TransactionFlags,
    ) -> Result<()> {
        match code {
            OPEN_OUTPUT_FILE_TRANSACTION => {
                self.check_interface(data)?;
                let path_str = data.read_string16()?.to_string();
                let path = Path::new(&path_str);
                let selinux_context = data.read_string16()?.to_string();
                let mode = data.read_string16()?.to_string();
                self.0
                    .lock()
                    .unwrap()
                    .open_file(path, &selinux_context, &mode)?;
                if let Some(reply) = reply {
                    unsafe { reply.write_no_exception()?; }
                }
                Ok(())
            }
            _ => Err(Error::UNKNOWN_TRANSACTION),
        }
    }
}
