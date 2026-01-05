use std::{marker::PhantomData, net::Ipv4Addr};

use pnet::{
    packet::{
        ethernet::MutableEthernetPacket,
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        tcp::{MutableTcpPacket, TcpOption, TcpPacket},
        udp::{MutableUdpPacket, UdpPacket},
    },
    util::MacAddr,
};

use {ipv4::Ipv4, tcp::Tcp, udp::Udp};

mod ethernet;
mod ipv4;
mod tcp;
mod udp;

// Headers lengths
const ETH_LEN: usize = 14;
const IPV4_BASE_LEN: usize = 20;
const ETHIPV4_LEN: usize = ETH_LEN + IPV4_BASE_LEN;
const UDP_LEN: usize = 8;
const TCP_BASE_LEN: usize = 20;

// All the various states of the builder
pub struct Uninitialized;
pub struct Arp;

pub struct PacketBuilder<const N: usize, T = Uninitialized> {
    t: PhantomData<T>,
    buffer: [u8; N],
    len: usize,
}

impl<const N: usize, T> Clone for PacketBuilder<N, T> {
    fn clone(&self) -> Self {
        Self {
            t: PhantomData,
            buffer: self.buffer,
            len: self.len,
        }
    }
}

pub trait Packet: Sized + Clone {
    const MAX_LEN: usize;

    fn buffer(&self) -> &[u8];
    fn buffer_mut(&mut self) -> &mut [u8];
    fn len(&self) -> usize;
    fn set_len(&mut self, len: usize);

    fn source_mac(self, source_mac: MacAddr) -> Self;
    fn dest_mac(self, dest_mac: MacAddr) -> Self;
}

impl<const N: usize, T> Packet for PacketBuilder<N, T> {
    const MAX_LEN: usize = N;

    fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    fn source_mac(mut self, source_mac: MacAddr) -> Self {
        let mut pkt = MutableEthernetPacket::new(&mut self.buffer).unwrap();
        pkt.set_source(source_mac);
        self
    }

    fn dest_mac(mut self, dest_mac: MacAddr) -> Self {
        let mut pkt = MutableEthernetPacket::new(&mut self.buffer).unwrap();
        pkt.set_destination(dest_mac);
        self
    }
}

pub trait PacketIpv4: Packet {
    fn ttl(mut self, ttl: u8) -> Self {
        let mut pkt = MutableIpv4Packet::new(&mut self.buffer_mut()[ETH_LEN..]).unwrap();
        pkt.set_ttl(ttl);
        self
    }

    fn source_ip(mut self, source_ip: Ipv4Addr) -> Self {
        let mut pkt = MutableIpv4Packet::new(&mut self.buffer_mut()[ETH_LEN..]).unwrap();
        pkt.set_source(source_ip);
        self
    }

    fn destination_ip(mut self, destination_ip: Ipv4Addr) -> Self {
        let mut pkt = MutableIpv4Packet::new(&mut self.buffer_mut()[ETH_LEN..]).unwrap();
        pkt.set_destination(destination_ip);
        self
    }

    fn get_source_ip(&self) -> Ipv4Addr {
        let pkt = Ipv4Packet::new(&self.buffer()[ETH_LEN..]).unwrap();
        pkt.get_source()
    }

    fn get_destination_ip(&self) -> Ipv4Addr {
        let pkt = Ipv4Packet::new(&self.buffer()[ETH_LEN..]).unwrap();
        pkt.get_destination()
    }

    fn calc_ipv4_total_len(&self) -> usize {
        self.len() - ETH_LEN
    }

    fn payload(mut self, payload: &[u8]) -> Option<Self> {
        if Self::MAX_LEN < ETH_LEN + IPV4_BASE_LEN + payload.len() {
            return None;
        }

        self.buffer_mut()[ETHIPV4_LEN..].copy_from_slice(payload);
        Some(self)
    }
}

impl<const N: usize> PacketIpv4 for PacketBuilder<N, Ipv4> {}
impl<const N: usize> PacketIpv4 for PacketBuilder<N, Udp> {}
impl<const N: usize> PacketIpv4 for PacketBuilder<N, Tcp> {}

pub trait PacketTcp: PacketIpv4 {
    fn sequence(mut self, seq: u32) -> Self {
        let mut pkt = MutableTcpPacket::new(&mut self.buffer_mut()[ETHIPV4_LEN..]).unwrap();
        pkt.set_sequence(seq);
        self
    }

    fn acknowledgement(mut self, ack: u32) -> Self {
        let mut pkt = MutableTcpPacket::new(&mut self.buffer_mut()[ETHIPV4_LEN..]).unwrap();
        pkt.set_acknowledgement(ack);
        self
    }

    fn flags(mut self, flags: u8) -> Self {
        let mut pkt = MutableTcpPacket::new(&mut self.buffer_mut()[ETHIPV4_LEN..]).unwrap();
        pkt.set_flags(flags);
        self
    }

    fn window(mut self, window: u16) -> Self {
        let mut pkt = MutableTcpPacket::new(&mut self.buffer_mut()[ETHIPV4_LEN..]).unwrap();
        pkt.set_window(window);
        self
    }

    fn calc_data_offset(options: &[TcpOption]) -> u8 {
        5u8 + (options
            .iter()
            .map(|opt| match opt.length.len() {
                1 => u8::from_be_bytes([opt.length[0]]),
                0 => 1,
                _ => 0,
            })
            .sum::<u8>()
            / 4)
    }

    fn get_data_offset(&self) -> u8 {
        let pkt = TcpPacket::new(&self.buffer()[ETHIPV4_LEN..]).unwrap();
        Self::calc_data_offset(&pkt.get_options())
    }

    fn options(mut self, options: &[TcpOption]) -> Option<Self> {
        let prev_data_offset = self.get_data_offset();
        let new_data_offset = Self::calc_data_offset(options);
        let new_len =
            (self.len() - (prev_data_offset as usize * 4)) + (new_data_offset as usize * 4);

        let mut pkt = MutableTcpPacket::new(&mut self.buffer_mut()[ETHIPV4_LEN..]).unwrap();

        if Self::MAX_LEN < new_len {
            return None;
        }

        pkt.set_data_offset(new_data_offset);
        pkt.set_options(options);

        self.set_len(new_len);
        Some(self)
    }

    fn header_len(&self) -> usize {
        self.get_data_offset() as usize * 4
    }
}

impl<const N: usize> PacketTcp for PacketBuilder<N, Tcp> {}

pub trait HasPorts: PacketIpv4 {
    // Get the offset where the protocol header starts
    fn protocol_offset() -> usize {
        // Standard IPv4 + Ethernet header sizes
        ETH_LEN + IPV4_BASE_LEN
    }

    fn source_port(self, source_port: u16) -> Self;
    fn dest_port(self, dest_port: u16) -> Self;

    fn get_source_port(&self) -> u16;
    fn get_dest_port(&self) -> u16;
}

impl<const N: usize> HasPorts for PacketBuilder<N, Tcp> {
    fn source_port(mut self, source_port: u16) -> Self {
        let mut pkt = MutableTcpPacket::new(&mut self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.set_source(source_port);
        self
    }

    fn dest_port(mut self, dest_port: u16) -> Self {
        let mut pkt = MutableTcpPacket::new(&mut self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.set_destination(dest_port);
        self
    }

    fn get_source_port(&self) -> u16 {
        let pkt = TcpPacket::new(&self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.get_source()
    }

    fn get_dest_port(&self) -> u16 {
        let pkt = TcpPacket::new(&self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.get_destination()
    }
}

impl<const N: usize> HasPorts for PacketBuilder<N, Udp> {
    fn source_port(mut self, source_port: u16) -> Self {
        let mut pkt = MutableUdpPacket::new(&mut self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.set_source(source_port);
        self
    }

    fn dest_port(mut self, dest_port: u16) -> Self {
        let mut pkt = MutableUdpPacket::new(&mut self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.set_destination(dest_port);
        self
    }

    fn get_source_port(&self) -> u16 {
        let pkt = UdpPacket::new(&self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.get_source()
    }

    fn get_dest_port(&self) -> u16 {
        let pkt = UdpPacket::new(&self.buffer[Self::protocol_offset()..]).unwrap();
        pkt.get_destination()
    }
}

fn build_ipv4(buffer: &mut [u8], len: usize) -> &[u8] {
    let total_len = len - ETH_LEN;

    let mut pkt = MutableIpv4Packet::new(&mut buffer[ETH_LEN..ETH_LEN + total_len]).unwrap();

    pkt.set_total_length(total_len as u16);
    pkt.set_checksum(pnet::packet::ipv4::checksum(&pkt.to_immutable()));

    &buffer[0..len]
}

pub trait CanBuild: PacketIpv4 {
    fn build<'a>(&'a mut self) -> &'a [u8];
}

impl<const N: usize> CanBuild for PacketBuilder<N, Ipv4> {
    fn build<'a>(&'a mut self) -> &'a [u8] {
        build_ipv4(&mut self.buffer, self.len)
    }
}

impl<const N: usize> CanBuild for PacketBuilder<N, Udp> {
    fn build<'a>(&'a mut self) -> &'a [u8] {
        let source_ip = self.get_source_ip();
        let dest_ip = self.get_destination_ip();

        let mut pkt = MutableUdpPacket::new(&mut self.buffer[ETHIPV4_LEN..self.len]).unwrap();
        pkt.set_length(self.len as u16 - ETHIPV4_LEN as u16);

        pkt.set_checksum(pnet::packet::udp::ipv4_checksum(
            &pkt.to_immutable(),
            &source_ip,
            &dest_ip,
        ));

        build_ipv4(&mut self.buffer, self.len)
    }
}

impl<const N: usize> CanBuild for PacketBuilder<N, Tcp> {
    fn build<'a>(&'a mut self) -> &'a [u8] {
        let source_ip = self.get_source_ip();
        let dest_ip = self.get_destination_ip();
        let pkt_len = self.header_len();

        let mut pkt =
            MutableTcpPacket::new(&mut self.buffer[ETHIPV4_LEN..ETHIPV4_LEN + pkt_len]).unwrap();

        pkt.set_checksum(pnet::packet::tcp::ipv4_checksum(
            &pkt.to_immutable(),
            &source_ip,
            &dest_ip,
        ));

        build_ipv4(&mut self.buffer, self.len)
    }
}
