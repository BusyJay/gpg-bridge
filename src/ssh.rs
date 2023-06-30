// Refer https://github.com/gpg/gnupg/blob/master/agent/gpg-agent.c#L2528

use crate::util::other_error;
use core::slice;
use log::trace;
use std::ffi::c_void;
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::ptr;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;
use windows::core::HSTRING;
use windows::h;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LPARAM, WPARAM};
use windows::Win32::System::DataExchange::COPYDATASTRUCT;
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE, MEMORYMAPPEDVIEW_HANDLE,
};
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SendMessageW, WM_COPYDATA};

/// A magic value used with WM_COPYDATA.
const PUTTY_IPC_MAGIC: usize = 0x804e50ba;
const FILE_MAP_NAME: &'static HSTRING = h!("gpg_bridge");
const PAGEANT_WINDOW_NAME: &'static HSTRING = h!("Pageant\0");

/// To avoid surprises we limit the size of the mapped IPC file to this
/// value.  Putty currently (0.62) uses 8k, thus 16k should be enough
/// for the foreseeable future.  */
pub const PUTTY_IPC_MAXLEN: usize = 16384;

static CONCURRENCY: Semaphore = Semaphore::const_new(4);
static TOKEN: parking_lot::Mutex<u8> = parking_lot::const_mutex(0);

fn find_available_token() -> u8 {
    let mut token = TOKEN.lock();
    let mut mask = 1;
    for _ in 0..4 {
        if *token & mask == 0 {
            *token |= mask;
            return mask;
        }
        mask <<= 1;
    }
    unreachable!()
}

fn release_token(mask: u8) {
    let mut token = TOKEN.lock();
    *token &= !mask;
}

pub struct Handler {
    handle: HANDLE,
    view: MEMORYMAPPEDVIEW_HANDLE,
    view_ptr: *mut u8,
    limit: usize,
    mask: u8,
    name: String,
    _permit: SemaphorePermit<'static>,
    received: usize,
    replied: usize,
}

unsafe impl Send for Handler {}

impl Handler {
    pub async fn new() -> io::Result<Handler> {
        let permit = CONCURRENCY.acquire().await.unwrap();
        let mask = find_available_token();
        let name = HSTRING::from(format!("{}-{}\0", FILE_MAP_NAME, mask));
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                Some(ptr::null()),
                PAGE_READWRITE,
                0,
                PUTTY_IPC_MAXLEN as u32,
                &name,
            )
        };

        let handle = match handle {
            Ok(handle) => handle,
            Err(_e) => {
                release_token(mask);
                return Err(other_error(format!(
                    "failed to create file mapping: {}",
                    Error::last_os_error()
                )));
            }
        };

        let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, PUTTY_IPC_MAXLEN) };

        let view = match view {
            Ok(view) => view,
            Err(_e) => {
                unsafe {
                    CloseHandle(handle);
                }
                release_token(mask);
                return Err(other_error(format!(
                    "failed to map view of file: {}",
                    Error::last_os_error()
                )));
            }
        };

        Ok(Handler {
            handle,
            view,
            view_ptr: view.0 as *mut u8,
            limit: PUTTY_IPC_MAXLEN,
            mask,
            name: name.to_string(),
            _permit: permit,
            received: 0,
            replied: 0,
        })
    }

    pub async fn process_one(
        &mut self,
        reader: &mut Pin<Box<dyn AsyncRead + Send + '_>>,
    ) -> io::Result<Option<&[u8]>> {
        let len_bytes = unsafe { slice::from_raw_parts_mut(self.view_ptr, 4) };
        if let Err(e) = reader.read_exact(len_bytes).await {
            if e.kind() == ErrorKind::UnexpectedEof {
                return Ok(None);
            } else {
                return Err(e);
            }
        }
        let len = u32::from_be(unsafe { (self.view_ptr as *mut u32).read_unaligned() }) as usize + 4;
        if len >= self.limit {
            return Err(other_error(format!(
                "message too large: {} >= {}",
                len + 4,
                self.limit
            )));
        }
        self.received += len;
        let req = unsafe { slice::from_raw_parts_mut(self.view_ptr.add(4), len - 4) };
        reader.read_exact(req).await?;
        trace!("recv request {:?}", String::from_utf8_lossy(req));

        let win = unsafe {
            FindWindowW(
                PAGEANT_WINDOW_NAME,
                PAGEANT_WINDOW_NAME,
            )
        };


        if win.0 == 0 {
            return Err(other_error(format!(
                "can't contact gpg agent: {}",
                Error::last_os_error()
            )));
        }
        let copy_data = COPYDATASTRUCT {
            dwData: PUTTY_IPC_MAGIC,
            cbData: self.name.len() as u32,
            lpData: self.name.as_mut_ptr() as *mut c_void,
        };
        let res = unsafe {
            SendMessageW(
                win,
                WM_COPYDATA,
                WPARAM(0),
                LPARAM((&copy_data) as *const _ as _),
            )
        };
        if res.0 == 0 {
            return Err(other_error(format!(
                "failed to send message: {}",
                Error::last_os_error()
            )));
        }

        let len = u32::from_be(unsafe { (self.view_ptr as *mut u32).read_unaligned() }) as usize + 4;
        if len > self.limit {
            return Err(other_error(format!(
                "response too large: {} > {}",
                len + 4,
                self.limit
            )));
        }
        self.replied += len;
        unsafe { Ok(Some(slice::from_raw_parts(self.view_ptr, len))) }
    }

    pub fn received(&self) -> usize {
        self.received
    }

    pub fn replied(&self) -> usize {
        self.replied
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        unsafe {
            ptr::write_bytes(self.view_ptr, 0, self.limit);
            if self.view.0 != 0 {
                UnmapViewOfFile(self.view);
            }
            CloseHandle(self.handle);
        }
        release_token(self.mask);
    }
}
