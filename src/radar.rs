use ipnetwork::IpNetwork;
use pnet::datalink::NetworkInterface;

use std::sync::{mpsc, RwLock};

use std::io::{self};
use std::sync::Arc;

use crate::listener::{self, Listener};
use crate::net::arp::table::ArpTable;
use crate::settings::Settings;

#[derive(Default, Copy, Clone)]
pub struct RadarStats {
    pub sent: usize,
    pub received: usize,
    pub dropped: usize,
    pub pps: usize, // Packets per second
}

struct InnerRadar {
    settings: Settings,
    listener: Listener,
    arptable: ArpTable,
    stats: RwLock<RadarStats>,
}

pub struct Radar {
    inner: Arc<InnerRadar>,
}

impl Clone for Radar {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Radar {
    pub fn new(settings: Settings) -> io::Result<Self> {
        let radar = Self {
            inner: Arc::new(InnerRadar {
                settings: settings.clone(),
                listener: Listener::new(settings.clone()),
                arptable: ArpTable::new(),
                stats: Default::default(),
            }),
        };

        radar.sub_arp_reply();

        Ok(radar)
    }

    pub fn subscribe(&self) -> mpsc::Receiver<Arc<listener::Event>> {
        self.inner.listener.subscribe()
    }

    pub fn get_iface(&self) -> NetworkInterface {
        self.inner.settings.interface.clone()
    }

    pub fn get_iface_subnets(&self) -> Vec<IpNetwork> {
        self.inner.settings.interface.ips.clone()
    }

    pub fn get_stats(&self) -> RadarStats {
        *self.inner.stats.read().unwrap()
    }

    fn sub_arp_reply(&self) {
        let self_ref = self.clone();

        std::thread::spawn(move || {
            let rx = self_ref.subscribe();

            while self_ref.inner.listener.is_running() {
                if let Ok(event) = rx.recv() {
                    if let listener::Event::ArpReply { ip, mac } = event.as_ref() {
                        self_ref.inner.arptable.set(*ip, *mac);
                    }
                }
            }
        });
    }

    pub fn get_arp_table(&self) -> ArpTable {
        self.inner.arptable.clone()
    }
}
