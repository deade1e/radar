use std::net::Ipv4Addr;

mod tlv;

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum DhcpMessageType {
    DhcpDiscover = 1,
    DhcpOffer = 2,
    DhcpRequest = 3,
    DhcpDecline = 4,
    DhcpAck = 5,
    DhcpNak = 6,
    DhcpRelease = 7,
    Unknown = 0xFF,
}

impl From<u8> for DhcpMessageType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::DhcpDiscover,
            0x02 => Self::DhcpOffer,
            0x03 => Self::DhcpRequest,
            0x04 => Self::DhcpDecline,
            0x05 => Self::DhcpAck,
            0x06 => Self::DhcpNak,
            0x07 => Self::DhcpRelease,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum DhcpOption {
    SubnetMask(Vec<u8>) = 1,
    Router(Vec<u8>) = 3,
    TimeServer(Vec<u8>) = 4,
    NameServer(Vec<u8>) = 5,
    DomainNameServer(Vec<u8>) = 6,
    Hostname(String) = 12,
    RequestIpAddress(Ipv4Addr) = 50,
    IpAddressLeaseTime(Vec<u8>) = 51,
    OptionOverload(Vec<u8>) = 52,
    DhcpMessageType(DhcpMessageType) = 53,
    DhcpServer(Vec<u8>) = 54,
    ClientIdentifier(Vec<u8>) = 61,
    Unknown = 0xFF,
}

impl DhcpOption {
    pub fn from_buffer(value: &[u8]) -> Vec<Self> {
        let mut parser = tlv::TlvParser::new(value);
        let entries = parser.parse_all();
        let mut options = vec![];

        for entry in entries {
            if entry.value.is_empty() {
                continue;
            }

            let option = match entry.tlv_type {
                1 => Some(Self::SubnetMask(entry.value)),
                3 => Some(Self::Router(entry.value)),
                4 => Some(Self::TimeServer(entry.value)),
                5 => Some(Self::NameServer(entry.value)),
                6 => Some(Self::DomainNameServer(entry.value)),
                12 => match String::from_utf8(entry.value) {
                    Ok(hostname) => Some(Self::Hostname(hostname)),
                    Err(_) => None,
                },
                50 => match entry.value.len() == 4 {
                    true => Some(Self::RequestIpAddress(Ipv4Addr::from(
                        <[u8; 4]>::try_from(entry.value).unwrap(),
                    ))),
                    false => None,
                },
                51 => Some(Self::IpAddressLeaseTime(entry.value)),
                52 => Some(Self::OptionOverload(entry.value)),
                53 => Some(Self::DhcpMessageType(entry.value[0].into())),
                54 => Some(Self::DhcpServer(entry.value)),
                61 => Some(Self::ClientIdentifier(entry.value)),
                _ => Some(Self::Unknown),
            };

            if let Some(option) = option {
                options.push(option);
            }
        }

        options
    }

    pub fn get_requested_ip_address(options: &[DhcpOption]) -> Option<Ipv4Addr> {
        for option in options {
            if let DhcpOption::RequestIpAddress(ip) = option {
                return Some(*ip);
            }
        }

        None
    }

    pub fn get_clientidentifier(options: &[DhcpOption]) -> Option<Vec<u8>> {
        for option in options {
            if let DhcpOption::ClientIdentifier(ci) = option {
                return Some(ci.clone());
            }
        }

        None
    }

    pub fn get_hostname(options: &[DhcpOption]) -> Option<String> {
        for option in options {
            if let DhcpOption::Hostname(hostname) = option {
                return Some(hostname.clone());
            }
        }

        None
    }
}
