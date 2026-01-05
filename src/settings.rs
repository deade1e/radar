use std::net::Ipv4Addr;

use pnet::datalink::{self, NetworkInterface};

use crate::route_table::Ipv4RouteTable;

#[derive(Clone)]
pub struct Settings {
    pub interface: NetworkInterface,
}

impl Settings {
    pub fn get_iface(name: &str) -> Option<NetworkInterface> {
        let interfaces = datalink::interfaces();

        interfaces
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == name)
    }

    pub fn by_iface(name: &str) -> Option<Self> {
        let iface = Self::get_iface(name);

        if let Some(iface) = iface {
            Some(Self { interface: iface })
        } else {
            None
        }
    }

    pub fn try_default() -> Option<Self> {
        let table: Ipv4RouteTable = Default::default();

        for e in table.into_iter() {
            if e.dest == Ipv4Addr::from_bits(0) && e.mask == Ipv4Addr::from_bits(0) {
                return Some(Self {
                    interface: Self::get_iface(&e.iface).unwrap(),
                });
            }
        }
        None
    }
}
