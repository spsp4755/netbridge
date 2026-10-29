//! One app per Windows session: a second launch wakes the running copy and exits.
use eframe::egui::{self, ViewportCommand};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

const MUTEX: &str = "Local\\NetBridgeClient.Instance";
const EVENT: &str = "Local\\NetBridgeClient.Show";

/// Held for the life of the process; the mutex and event close with it.
pub struct Instance {
    _mutex: HANDLE,
    event: HANDLE,
}

unsafe impl Send for Instance {}

/// `None` when another copy already runs (it has been told to show its window).
pub fn acquire() -> Option<Instance> {
    unsafe {
        let mutex = CreateMutexW(std::ptr::null(), 0, wide(MUTEX).as_ptr());
        if !mutex.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            let ev = OpenEventW(EVENT_MODIFY_STATE, 0, wide(EVENT).as_ptr());
            if !ev.is_null() {
                SetEvent(ev);
                CloseHandle(ev);
            }
            CloseHandle(mutex);
            return None;
        }
        let event = CreateEventW(std::ptr::null(), 0, 0, wide(EVENT).as_ptr());
        Some(Instance { _mutex: mutex, event })
    }
}

impl Instance {
    /// Brings the window back whenever a second launch signals.
    pub fn on_show(self, ctx: egui::Context, wake: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        if self.event.is_null() {
            return;
        }
        std::thread::spawn(move || {
            let inst = self;
            while unsafe { WaitForSingleObject(inst.event, INFINITE) } == WAIT_OBJECT_0 {
                // a second launch may have left files in the outbox
                wake.store(true, std::sync::atomic::Ordering::SeqCst);
                ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(ViewportCommand::Focus);
                ctx.request_repaint();
            }
        });
    }
}
