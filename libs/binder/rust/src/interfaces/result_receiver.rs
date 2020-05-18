//! ResultReceiver interface.

use crate::binder::{IBinder, TransactionCode, TransactionFlags};
use crate::parcel::Parcel;
use crate::proxy::Handle;
use crate::{Binder, Error, Interface, Result};

use std::sync::Mutex;

declare_binder_interface!(BpResultReceiver: IResultReceiver);

const SEND_TRANSACTION: TransactionCode = Interface::FIRST_CALL_TRANSACTION;

pub trait IResultReceiver {
    const INTERFACE_DESCRIPTOR: &'static str = "com.android.internal.app.IResultReceiver";

    fn send(&mut self, result_code: i32) -> Result<()>;
}

impl IResultReceiver for BpResultReceiver {
    fn send(&mut self, result_code: i32) -> Result<()> {
        let mut data = Parcel::new();
        unsafe {
            data.write_interface_token(&Self::INTERFACE_DESCRIPTOR.into())?;
        }
        data.write_i32(result_code)?;

        self.remote_mut()
            .transact(SEND_TRANSACTION, &data, None, Interface::FLAG_ONEWAY)
    }
}

pub struct ResultReceiver(Mutex<ResultReceiverClosure>);

pub struct ResultReceiverClosure(Box<dyn Fn(i32) + Send + 'static>);

impl IResultReceiver for ResultReceiverClosure {
    fn send(&mut self, result_code: i32) -> Result<()> {
        Ok(self.0(result_code))
    }
}

impl IResultReceiver for ResultReceiver {
    fn send(&mut self, result_code: i32) -> Result<()> {
        // If another thread panicked while holding the mutex we cannot access
        // it.
        self.0
            .get_mut()
            .or(Err(Error::DEAD_OBJECT))?
            .send(result_code)
    }
}

impl ResultReceiver {
    pub fn new<C>(callback: C) -> Self
    where
        C: Fn(i32) + Send + 'static,
    {
        Self(Mutex::new(ResultReceiverClosure(Box::new(callback))))
    }
}

impl Binder for ResultReceiver {
    const INTERFACE_DESCRIPTOR: &'static str = <Self as IResultReceiver>::INTERFACE_DESCRIPTOR;

    fn on_transact(
        &self,
        code: TransactionCode,
        data: &Parcel,
        reply: Option<&mut Parcel>,
        _flags: TransactionFlags,
    ) -> Result<()> {
        match code {
            SEND_TRANSACTION => {
                self.check_interface(data)?;
                let result_code = data.read_i32()?;
                self.0.lock().unwrap().send(result_code)?;
                if let Some(reply) = reply {
                    unsafe { reply.write_no_exception()?; }
                }
                Ok(())
            }
            _ => Err(Error::UNKNOWN_TRANSACTION),
        }
    }
}
