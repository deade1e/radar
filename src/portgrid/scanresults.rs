use std::{collections::HashMap, net::Ipv4Addr};

use pnet::util::MacAddr;
use rangemap::RangeSet;
use serde::ser::SerializeSeq;
use serde::Serialize;

/// Single IP scan result
#[derive(Serialize)]
pub struct IpScanResult {
    #[serde(serialize_with = "serialize_rangeset")]
    open: RangeSet<u16>,

    // TODO: Implement also ports that actively replied with RST
    #[serde(serialize_with = "serialize_rangeset")]
    closed: RangeSet<u16>,

    #[serde(serialize_with = "crate::listener::serialize_optional_mac_addr")]
    mac: Option<MacAddr>,
}

impl IpScanResult {
    pub fn new() -> Self {
        IpScanResult {
            open: RangeSet::new(),
            closed: RangeSet::new(),
            mac: None,
        }
    }

    pub fn add_open(&mut self, port: u16) {
        self.open.insert(port..port + 1)
    }

    pub fn check_open(&self, port: u16) -> bool {
        self.open.contains(&port)
    }
}

/// Full scan results
#[derive(Serialize)]
#[serde(transparent)]
pub struct ScanResults(
    #[serde(serialize_with = "serialize_scanresults")] pub HashMap<Ipv4Addr, IpScanResult>,
);

impl ScanResults {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
}

#[derive(Serialize)]
struct IpResultEntry<'a> {
    ip: String,
    #[serde(flatten)]
    result: &'a IpScanResult,
}

fn serialize_scanresults<S>(
    map: &HashMap<Ipv4Addr, IpScanResult>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;

    for (ip, result) in map {
        let entry = IpResultEntry {
            ip: ip.to_string(),
            result,
        };
        seq.serialize_element(&entry)?;
    }

    seq.end()
}

fn serialize_rangeset<S>(rs: &RangeSet<u16>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let ranges: Vec<_> = rs.iter().collect();
    let mut seq = serializer.serialize_seq(Some(ranges.len()))?;

    for range in ranges {
        if range.start + 1 == range.end {
            seq.serialize_element(&range.start)?;
        } else {
            seq.serialize_element(&format!("{}-{}", range.start, range.end - 1))?;
        }
    }

    seq.end()
}
