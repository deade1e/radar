use std::ops::RangeInclusive;

use ipnetwork::Ipv4Network;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigScan {
    /// The subnet to scan
    pub subnet: Ipv4Network,

    /// The ports to poke for each IP
    #[serde(deserialize_with = "deserialize_range")]
    #[serde(serialize_with = "serialize_range")]
    pub ports: RangeInclusive<u16>,

    /// If scan UDP ports instead of TCP
    pub udp: bool,

    /// The maximum rate of packets to be sent via the interface
    pub max_rate: Option<usize>,

    /// The url where to push scan results
    pub push_url: String,

    /// Cron expression to follow to
    pub cron: String,
}

impl ConfigScan {
    pub fn ports_str(&self) -> String {
        let start = self.ports.start();
        let end = self.ports.end();

        match start == end {
            true => format!("{}", start),
            false => format!("{}-{}", start, end),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The delay between every fetch of the config
    pub delay: u32,

    /// Scan sub-object
    pub scan: ConfigScan,
}

fn deserialize_range<'de, D>(deserializer: D) -> Result<RangeInclusive<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    if let Some(dash_pos) = s.find('-') {
        let start: u16 = s[..dash_pos].parse().map_err(serde::de::Error::custom)?;
        let end: u16 = s[dash_pos + 1..]
            .parse()
            .map_err(serde::de::Error::custom)?;
        Ok(start..=end)
    } else {
        let num: u16 = s.parse().map_err(serde::de::Error::custom)?;
        Ok(num..=num)
    }
}

fn serialize_range<S>(range: &RangeInclusive<u16>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let start = range.start();
    let end = range.end();
    let s = match start == end {
        true => format!("{}", start),
        false => format!("{}-{}", start, end),
    };
    serializer.serialize_str(&s)
}
