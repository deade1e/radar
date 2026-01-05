use super::{PacketBuilder, ETHIPV4_LEN, ETH_LEN, IPV4_BASE_LEN};

/// Ipv4 state
pub struct Ipv4;

/// It calculates the IPv4 header length of the current packet.
/// As of now it returns a static value of 20 because there is no usage of IPv4 options
fn ipv4_header_len() -> usize {
    IPV4_BASE_LEN
}

/// Methods that are available only in the Ipv4 state
impl<const N: usize> PacketBuilder<N, Ipv4> {
    fn payload(mut self, payload: &[u8]) -> Option<PacketBuilder<N, Ipv4>> {
        if N < ETH_LEN + ipv4_header_len() + payload.len() {
            return None;
        }
        self.buffer[ETHIPV4_LEN..].copy_from_slice(payload);
        Some(self)
    }
}
