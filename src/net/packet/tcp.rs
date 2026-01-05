use std::marker::PhantomData;

use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, tcp::MutableTcpPacket};

use super::{ipv4::Ipv4, PacketBuilder, ETHIPV4_LEN, ETH_LEN, TCP_BASE_LEN};

/// Tcp state
pub struct Tcp;

/// Implement the tcp switch method in the Ipv4 state
impl<const N: usize> PacketBuilder<N, Ipv4> {
    pub fn tcp(mut self, source_port: u16, dest_port: u16) -> Option<PacketBuilder<N, Tcp>> {
        if N < self.len + TCP_BASE_LEN {
            return None;
        }

        {
            let mut pkt = MutableIpv4Packet::new(&mut self.buffer[ETH_LEN..]).unwrap();
            pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        }

        let mut pkt = MutableTcpPacket::new(&mut self.buffer[ETHIPV4_LEN..]).unwrap();

        pkt.set_source(source_port);
        pkt.set_destination(dest_port);
        pkt.set_data_offset(5); // Data offset is always at least 5

        Some(PacketBuilder::<N, Tcp> {
            t: PhantomData,
            buffer: self.buffer,
            len: self.len + TCP_BASE_LEN,
        })
    }
}
