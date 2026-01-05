use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use perfect_rand::PerfectRng;
use std::ops::RangeInclusive;

fn ipv4_to_u32(ipv4: Ipv4Addr) -> u32 {
    let octets = ipv4.octets();
    ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32)
}

#[derive(Eq, PartialEq, Hash)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: u16,
}

pub struct TargetIter {
    /// Predictable shuffler without memory pre-allocation
    randomizer: PerfectRng,
    subnet: Ipv4Network,
    masked_subnet: u32,
    i: u64,
    /// Total number of IPs to be scanned
    max_rand: u64,
    port_start: u16,
}

impl TargetIter {
    pub fn new(subnet: Ipv4Network, ports: RangeInclusive<u16>) -> Self {
        let ip_bits = 32 - subnet.prefix();

        let mask = match subnet.prefix() > 0 {
            true => !((1 << (ip_bits)) - 1),
            false => 0,
        };

        let masked_subnet = ipv4_to_u32(subnet.ip()) & mask;

        let max_rand = 2u64.pow(ip_bits as u32) * ports.len() as u64;
        let randomizer = PerfectRng::from_range(max_rand);

        Self {
            randomizer,
            subnet,
            masked_subnet,
            i: 0,
            max_rand,
            port_start: *ports.start(),
        }
    }
}

impl Iterator for TargetIter {
    type Item = Target;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == self.max_rand {
            return None;
        }

        let offset = self.randomizer.shuffle(self.i);

        let ip_bits = 32 - self.subnet.prefix();
        let ip_offset_mask = (1 << ip_bits) - 1;

        let ip_offset = offset & ip_offset_mask;
        let port = (offset >> ip_bits) as u16 + self.port_start;

        let ip = Ipv4Addr::from(
            (self.masked_subnet | ip_offset as u32)
                + (if self.subnet.prefix() < 31 { 1 } else { 0 }),
        );

        self.i += 1;

        Some(Target {
            ip,
            port: port as u16,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Target, TargetIter};

    #[test]
    fn target_iter_192_168() {
        let subnet = "192.168.1.0/24".parse().unwrap();

        let port_range = 1..=3;
        let tl = TargetIter::new(subnet, port_range.clone());

        let mut targets: HashMap<Target, bool> = HashMap::new();

        for target in tl {
            targets.insert(target, true);
        }

        for ip in subnet.iter().skip(1).take(subnet.size() as usize - 2) {
            for port in port_range.clone() {
                let target = Target { ip, port };

                println!("Checking if {ip}:{port} is present");
                assert!(targets.get(&target) == Some(&true));
            }
        }
    }

    #[test]
    fn target_iter_1_1_1_1_all_ports() {
        let subnet = "1.1.1.1".parse().unwrap();

        let port_range = 1..=65535;
        let tl = TargetIter::new(subnet, port_range.clone());

        let mut targets: HashMap<Target, bool> = HashMap::new();

        for target in tl {
            targets.insert(target, true);
        }

        for ip in subnet.iter() {
            for port in port_range.clone() {
                let target = Target { ip, port };

                println!("Checking if {ip}:{port} is present");
                assert!(targets.get(&target) == Some(&true));
            }
        }
    }

    #[test]
    fn target_iter_single_ip_single_port() {
        let subnet = "192.168.1.32/32".parse().unwrap();

        let port_range = 1..=1;
        let tl = TargetIter::new(subnet, port_range.clone());

        let mut targets: HashMap<Target, bool> = HashMap::new();

        for target in tl {
            targets.insert(target, true);
        }

        for ip in subnet.iter() {
            for port in port_range.clone() {
                let target = Target { ip, port };

                println!("Checking if {ip}:{port} is present");
                assert!(targets.get(&target) == Some(&true));
            }
        }
    }

    #[test]
    fn target_list_172_16_all_ports() {
        let subnet = "172.16.0.0/30".parse().unwrap();

        let port_range = 0..=65535;
        let tl = TargetIter::new(subnet, port_range.clone());

        let mut targets: HashMap<Target, bool> = HashMap::new();

        for target in tl {
            targets.insert(target, true);
        }

        for ip in subnet.iter().skip(1).take(subnet.size() as usize - 2) {
            for port in port_range.clone() {
                let target = Target { ip, port };

                println!("Checking if {ip}:{port} is present");
                assert!(targets.get(&target) == Some(&true));
            }
        }
    }
}
