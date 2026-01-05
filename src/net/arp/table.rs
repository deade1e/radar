use chrono::{DateTime, Utc};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone, Copy)]
pub struct ArpEntry {
    pub mac: MacAddr,
    time: DateTime<Utc>,
}

struct Inner {
    table: RwLock<HashMap<Ipv4Addr, ArpEntry>>,
}

pub(crate) struct ArpTable {
    inner: Arc<Inner>,
}

impl Clone for ArpTable {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl ArpTable {
    pub fn new() -> Self {
        let inner = Arc::new(Inner {
            table: Default::default(),
        });

        Self {
            inner: inner.clone(),
        }
    }

    // TODO: Borrow the ip
    pub fn get(&self, ip: Ipv4Addr) -> Option<ArpEntry> {
        let table = self.inner.table.read().unwrap();
        table.get(&ip).copied()
    }

    pub fn set(&self, ip: Ipv4Addr, mac: MacAddr) {
        let entry = ArpEntry {
            mac,
            time: Utc::now(),
        };
        self.inner.table.write().unwrap().entry(ip).or_insert(entry);
    }

    pub fn remove(&self, ip: Ipv4Addr) {
        self.inner.table.write().unwrap().remove(&ip);
    }

    pub fn clear(&self) {
        self.inner.table.write().unwrap().clear();
    }

    pub fn get_all(&self) -> Vec<(Ipv4Addr, ArpEntry)> {
        let table = self.inner.table.read().unwrap();
        table.iter().map(|(ip, entry)| (*ip, *entry)).collect()
    }

    pub fn get_older_than(&self, duration: chrono::Duration) -> Vec<(Ipv4Addr, ArpEntry)> {
        let table = self.inner.table.read().unwrap();
        table
            .iter()
            .filter(|(_, entry)| Utc::now() - entry.time > duration)
            .map(|(ip, entry)| (*ip, *entry))
            .collect()
    }

    pub fn get_younger_than(&self, duration: chrono::Duration) -> Vec<(Ipv4Addr, ArpEntry)> {
        let table = self.inner.table.read().unwrap();
        table
            .iter()
            .filter(|(_, entry)| Utc::now() - entry.time < duration)
            .map(|(ip, entry)| (*ip, *entry))
            .collect()
    }

    pub fn read_table(&self) -> RwLockReadGuard<'_, HashMap<Ipv4Addr, ArpEntry>> {
        self.inner.table.read().unwrap()
    }

    pub fn write_table(&self) -> RwLockWriteGuard<'_, HashMap<Ipv4Addr, ArpEntry>> {
        self.inner.table.write().unwrap()
    }
}
