use std::{net::Ipv4Addr, time::Duration};

use ipnetwork::IpNetwork;
use pnet::{
    datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
    util::MacAddr,
};

use crate::{
    listener::Event,
    net::{
        arp::table::ArpTable,
        interface::{get_default_gateway, get_eth_channel},
    },
    wait_for_event,
};

fn craft_arp_request(source_mac: &MacAddr, source_ip: &Ipv4Addr, target_ip: &Ipv4Addr) -> Vec<u8> {
    let mut buffer = [0u8; 42];

    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_source(*source_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);
    }

    {
        let mut arp_packet = MutableArpPacket::new(&mut buffer[14..]).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(*source_mac);
        arp_packet.set_sender_proto_addr(*source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(*target_ip);
    }

    buffer.to_vec()
}

pub fn query_arp_net(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    source_mac: &MacAddr,
    source_ip: &Ipv4Addr,
    ip_find: &Ipv4Addr,
    wait: Option<Duration>,
) -> Option<MacAddr> {
    let buffer = craft_arp_request(source_mac, source_ip, ip_find);

    tx.send_to(&buffer, None)?.unwrap();

    if let Some(wait) = wait {
        return wait_for_event!(rx, wait, Event::ArpReply { ip, mac } if ip == *ip_find => mac);
    } else {
        None
    }
}

pub fn query_arp(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    table: &ArpTable,
    source_mac: &MacAddr,
    source_ip: &Ipv4Addr,
    ip_find: &Ipv4Addr,
    wait: Option<Duration>,
) -> Option<MacAddr> {
    match table.get(*ip_find).map(|e| e.mac) {
        Some(mac) => Some(mac),
        None => match query_arp_net(tx, rx, source_mac, source_ip, ip_find, wait) {
            Some(mac) => {
                table.set(*ip_find, mac);
                Some(mac)
            }
            None => None,
        },
    }
}

pub struct ArpQuery<'a> {
    iface: &'a NetworkInterface,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    table: &'a ArpTable,
    source_mac: MacAddr,
}

impl<'a> ArpQuery<'a> {
    pub fn new(iface: &'a NetworkInterface, table: &'a ArpTable) -> Self {
        let source_mac = iface.mac.expect("Interface has no MAC");
        let (tx, rx) = get_eth_channel(iface).expect("Cannot access ethernet channel on interface");

        Self {
            iface,
            tx,
            rx,
            table,
            source_mac,
        }
    }

    pub fn resolve_mac(&mut self, ip: Ipv4Addr, wait: Option<Duration>) -> Option<MacAddr> {
        if !ip.is_private() {
            let gw = get_default_gateway(self.iface)?;
            return self.resolve_mac(gw, wait);
        }

        for subnet in self.iface.ips.iter() {
            let IpNetwork::V4(subnet) = subnet else {
                continue;
            };

            if subnet.contains(ip) {
                return query_arp(
                    &mut self.tx,
                    &mut self.rx,
                    self.table,
                    &self.source_mac,
                    &subnet.ip(),
                    &ip,
                    wait,
                );
            }
        }

        return None;
    }
}
