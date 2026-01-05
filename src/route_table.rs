use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
};

fn hex_to_ipv4(data: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    Ok(Ipv4Addr::from_bits(u32::from_le_bytes(
        hex::decode(data)?.as_slice().try_into()?,
    )))
}

pub struct Ipv4RouteEntry {
    pub iface: String,
    pub dest: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mask: Ipv4Addr,
}

pub struct Ipv4RouteTable {
    line_iter: std::iter::Skip<std::io::Lines<BufReader<File>>>,
}

impl Default for Ipv4RouteTable {
    fn default() -> Self {
        let file = File::open("/proc/net/route").unwrap();
        let reader = BufReader::new(file);
        Self {
            line_iter: reader.lines().skip(1),
        }
    }
}

impl Iterator for Ipv4RouteTable {
    type Item = Ipv4RouteEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(Ok(line)) = self.line_iter.next() else {
            return None;
        };

        let fields: Vec<&str> = line.split_whitespace().collect();

        Some(Ipv4RouteEntry {
            iface: fields[0].to_string(),
            dest: hex_to_ipv4(fields[1]).unwrap(),
            gateway: hex_to_ipv4(fields[2]).unwrap(),
            mask: hex_to_ipv4(fields[7]).unwrap(),
        })
    }
}
