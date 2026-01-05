use std::io;
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};

use pnet::datalink::Channel::Ethernet;

use crate::route_table::Ipv4RouteTable;

pub fn get_eth_channel(
    interface: &NetworkInterface,
) -> io::Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let Ethernet(tx, rx) = datalink::channel(interface, Default::default())? else {
        return Err(io::Error::other(format!("Unexpected type of channel")));
    };

    Ok((tx, rx))
}

pub fn calc_gateway(iface: &NetworkInterface, ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let table = Ipv4RouteTable::default();

    for entry in table {
        let Ok(subnet) = Ipv4Network::with_netmask(entry.dest, entry.mask) else {
            continue;
        };

        if entry.iface == iface.name && subnet.contains(ip) {
            return Some(entry.gateway);
        }
    }

    None
}

pub fn get_default_gateway(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    let table = Ipv4RouteTable::default();

    for entry in table {
        if entry.iface == iface.name && entry.dest == Ipv4Addr::from_octets([0, 0, 0, 0]) {
            return Some(entry.gateway);
        }
    }

    None
}
