use std::{marker::PhantomData, net::Ipv4Addr};

use pnet::{
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        ipv4::MutableIpv4Packet,
    },
    util::MacAddr,
};

use super::{ipv4::Ipv4, PacketBuilder, Uninitialized, ETH_LEN, IPV4_BASE_LEN};

pub struct Ethernet;

/// Methods that are available only in the Uninitialized state
impl<const N: usize> PacketBuilder<N, Uninitialized> {
    pub fn new(source_mac: MacAddr, dest_mac: MacAddr) -> Option<PacketBuilder<N, Ethernet>> {
        if N < ETH_LEN {
            return None;
        }

        let mut buffer = [0u8; N];

        let mut pkt = MutableEthernetPacket::new(&mut buffer).unwrap();
        pkt.set_source(source_mac);
        pkt.set_destination(dest_mac);

        Some(PacketBuilder::<N, Ethernet> {
            t: PhantomData,
            buffer,
            len: ETH_LEN,
        })
    }
}

/// Methods that are available only in the Ethernet state
impl<const N: usize> PacketBuilder<N, Ethernet> {
    pub fn ipv4(
        mut self,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) -> Option<PacketBuilder<N, Ipv4>> {
        if N < ETH_LEN + IPV4_BASE_LEN {
            return None;
        }

        {
            let mut pkt = MutableEthernetPacket::new(&mut self.buffer).unwrap();
            pkt.set_ethertype(EtherTypes::Ipv4);
        }

        let mut pkt = MutableIpv4Packet::new(&mut self.buffer[14..]).unwrap();
        pkt.set_version(4); //IPv4
        pkt.set_header_length(5); // 5 words (20 bytes) for header length

        // pkt.set_total_length(0); // Total length (IP header + payload)
        pkt.set_ttl(64);
        pkt.set_source(source_ip); // Source IP address
        pkt.set_destination(dest_ip); // Destination IP address

        Some(PacketBuilder::<N, Ipv4> {
            t: PhantomData,
            buffer: self.buffer,
            len: self.len + IPV4_BASE_LEN,
        })
    }
}
