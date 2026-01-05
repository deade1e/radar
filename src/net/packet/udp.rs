use std::marker::PhantomData;

use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, udp::MutableUdpPacket};

use super::{ipv4::Ipv4, Packet, PacketBuilder, ETHIPV4_LEN, ETH_LEN, UDP_LEN};

/// Udp state
pub struct Udp;

/// Methods that are available only in the Udp state
impl<const N: usize> PacketBuilder<N, Udp> {
    pub fn payload(mut self, payload: &[u8]) -> Option<PacketBuilder<N, Udp>> {
        // Storing it here because later self gets borrowed mutably
        let cur_len = self.len();

        if N < cur_len + payload.len() {
            return None;
        }

        self.buffer[cur_len..cur_len + payload.len()].copy_from_slice(payload);
        self.len = cur_len + payload.len();
        Some(self)
    }
}

/// Implement the udp switch method in the Ipv4 state
impl<const N: usize> PacketBuilder<N, Ipv4> {
    pub fn udp(mut self, source_port: u16, dest_port: u16) -> Option<PacketBuilder<N, Udp>> {
        if self.len + UDP_LEN > N {
            return None;
        }

        {
            let mut pkt = MutableIpv4Packet::new(&mut self.buffer[ETH_LEN..]).unwrap();
            pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        }

        let mut pkt = MutableUdpPacket::new(&mut self.buffer[ETHIPV4_LEN..]).unwrap();

        pkt.set_source(source_port);
        pkt.set_destination(dest_port);
        pkt.set_length(UDP_LEN as u16);

        Some(PacketBuilder::<N, Udp> {
            t: PhantomData,
            buffer: self.buffer,
            len: self.len + UDP_LEN,
        })
    }
}
