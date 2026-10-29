use netbridge_proto::Event;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Live WebSocket connections of this server's devices, keyed by device id.
#[derive(Default)]
pub struct Hub {
    conns: Mutex<HashMap<i64, Vec<UnboundedSender<Event>>>>,
}

impl Hub {
    pub fn register(&self, device_id: i64) -> UnboundedReceiver<Event> {
        let (tx, rx) = unbounded_channel();
        self.conns.lock().unwrap().entry(device_id).or_default().push(tx);
        rx
    }

    /// Delivers to every live connection of the device; true when at least one got it.
    pub fn push(&self, device_id: i64, ev: Event) -> bool {
        let mut conns = self.conns.lock().unwrap();
        let Some(list) = conns.get_mut(&device_id) else { return false };
        list.retain(|tx| tx.send(ev.clone()).is_ok());
        let any = !list.is_empty();
        if !any {
            conns.remove(&device_id);
        }
        any
    }

    /// Closes every connection of the device; their sockets end when the channel closes.
    pub fn drop_device(&self, device_id: i64) {
        self.conns.lock().unwrap().remove(&device_id);
    }

    pub fn online(&self) -> Vec<i64> {
        let mut conns = self.conns.lock().unwrap();
        conns.retain(|_, l| {
            l.retain(|tx| !tx.is_closed());
            !l.is_empty()
        });
        conns.keys().copied().collect()
    }

    pub fn is_online(&self, device_id: i64) -> bool {
        self.online().contains(&device_id)
    }
}
