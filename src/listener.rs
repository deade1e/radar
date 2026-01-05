use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::{net::Ipv4Addr, sync::mpsc};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::dhcp::DhcpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::{datalink, util::MacAddr};
use serde::{Serialize, Serializer};

use crate::net::dhcp::{DhcpMessageType, DhcpOption};
use crate::settings::Settings;

#[derive(Debug, Serialize)]
pub enum Event {
    ArpReply {
        ip: Ipv4Addr,
        #[serde(serialize_with = "serialize_mac_addr")]
        mac: MacAddr,
    },
    Syn {
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        #[serde(serialize_with = "serialize_payload")]
        packet: Vec<u8>,
    },
    SynAck {
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        ack: u32,
        #[serde(serialize_with = "serialize_payload")]
        packet: Vec<u8>,
    },
    Udp {
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        #[serde(serialize_with = "serialize_payload")]
        payload: Vec<u8>,
    },
    DhcpRequest {
        #[serde(serialize_with = "serialize_mac_addr")]
        source_mac: MacAddr,
        #[serde(serialize_with = "serialize_mac_addr")]
        dest_mac: MacAddr,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        hostname: Option<String>,
        #[serde(serialize_with = "serialize_optional_payload")]
        clientid: Option<Vec<u8>>,
        reqip: Option<Ipv4Addr>,
    },
    DhcpDiscover {
        #[serde(skip)]
        packet: DhcpPacket<'static>,
        #[serde(skip)]
        options: Vec<DhcpOption>,
    },
}

pub fn serialize_mac_addr<S>(value: &MacAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

pub fn serialize_optional_mac_addr<S>(
    value: &Option<MacAddr>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(m) => serializer.serialize_str(m.to_string().as_str()),
        None => serializer.serialize_none(),
    }
}

fn serialize_optional_payload<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(p) => serializer.serialize_str(&BASE64_STANDARD.encode(p)),
        None => serializer.serialize_none(),
    }
}

fn serialize_payload<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STANDARD.encode(value))
}

fn handle_dhcp(
    source_mac: MacAddr,
    dest_mac: MacAddr,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    packet: DhcpPacket<'static>,
) -> Option<Event> {
    let raw_options = packet.payload();

    if raw_options.len() < 4 {
        return None;
    }

    let options = DhcpOption::from_buffer(&raw_options[4..]);

    let hostname = DhcpOption::get_hostname(&options);
    let clientid = DhcpOption::get_clientidentifier(&options);
    let reqip = DhcpOption::get_requested_ip_address(&options);

    for option in &options {
        match option {
            DhcpOption::DhcpMessageType(DhcpMessageType::DhcpRequest) => {
                return Some(Event::DhcpRequest {
                    source_mac,
                    dest_mac,
                    source_ip,
                    dest_ip,
                    hostname,
                    clientid,
                    reqip,
                });
            }

            DhcpOption::DhcpMessageType(DhcpMessageType::DhcpDiscover) => {
                return Some(Event::DhcpDiscover { packet, options });
            }

            _ => {}
        };
    }

    return None;
}

pub fn frame_to_events(frame: &[u8]) -> Vec<Event> {
    let Some(ethpacket) = EthernetPacket::new(frame) else {
        return vec![];
    };

    let source_mac = ethpacket.get_source();
    let dest_mac = ethpacket.get_destination();

    match ethpacket.get_ethertype() {
        EtherTypes::Ipv4 => {
            let Some(ipv4packet) = Ipv4Packet::new(ethpacket.payload()) else {
                return vec![];
            };

            let source_ip = ipv4packet.get_source();
            let dest_ip = ipv4packet.get_destination();

            match ipv4packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let Some(tcppacket) = TcpPacket::new(ipv4packet.payload()) else {
                        return vec![];
                    };

                    let source_port = tcppacket.get_source();
                    let dest_port = tcppacket.get_destination();

                    let flags = tcppacket.get_flags();
                    let synack = TcpFlags::SYN | TcpFlags::ACK;

                    if flags & (synack) == synack {
                        let ack = tcppacket.get_acknowledgement();

                        return vec![Event::SynAck {
                            source_ip,
                            dest_ip,
                            source_port,
                            dest_port,
                            ack,
                            packet: ipv4packet.payload().to_vec(),
                        }];
                    } else if flags & TcpFlags::SYN == TcpFlags::SYN {
                        return vec![Event::Syn {
                            source_ip,
                            dest_ip,
                            source_port,
                            dest_port,
                            packet: ipv4packet.payload().to_vec(),
                        }];
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    let Some(udppacket) = UdpPacket::new(ipv4packet.payload()) else {
                        return vec![];
                    };

                    let source_port = udppacket.get_source();
                    let dest_port = udppacket.get_destination();
                    let payload = udppacket.payload();

                    let mut r = vec![];

                    r.push(Event::Udp {
                        source_ip,
                        dest_ip,
                        source_port,
                        dest_port,
                        payload: payload.to_vec(),
                    });

                    // Detecting for possible DHCP packet
                    if source_port == 68 && dest_port == 67 || source_port == 67 && dest_port == 68
                    {
                        // Trying to parse a DHCP packet
                        let Some(dhcp_packet) = DhcpPacket::owned(payload.to_vec()) else {
                            return r;
                        };

                        if let Some(event) =
                            handle_dhcp(source_mac, dest_mac, source_ip, dest_ip, dhcp_packet)
                        {
                            r.push(event);
                        }
                    }

                    return r;
                }

                _ => {}
            }
        }
        EtherTypes::Arp => {
            if let Some(arp_reply) = ArpPacket::new(ethpacket.payload()) {
                if arp_reply.get_operation() == ArpOperations::Reply {
                    let ip = arp_reply.get_sender_proto_addr();
                    let mac = arp_reply.get_sender_hw_addr();

                    return vec![Event::ArpReply { ip, mac }];
                }
            }
        }
        _ => {}
    }

    return vec![];
}

/// Wait for a specific event from a packet receiver within a timeout.
///
/// # Example
/// ```ignore
/// let reply = wait_for_event!(
///     rx,
///     Duration::from_secs(5),
///     Event::ArpReply { ip, mac } if ip == ip_find => (*mac)
/// );
/// ```
#[macro_export]
macro_rules! wait_for_event {
    ($rx:expr, $timeout:expr, $pat:pat $(if $cond:expr)? => $result:expr) => {{
        use std::time::Instant;

        let started = Instant::now();
        let mut found = None;

        while Instant::now().duration_since(started) < $timeout {
            let frame = match $rx.next() {
                Ok(frame) => frame,
                Err(_) => continue,
            };

            let events = crate::listener::frame_to_events(frame);
            #[allow(unreachable_patterns)]
            for ev in events.into_iter() {
                match ev {
                    $pat $(if $cond)? => {
                        found = Some($result);
                        break;
                    },
                    _ => {}
                }
            }

            if found.is_some() {
                break;
            }
        }

        found
    }};
}

struct InnerListener {
    settings: Settings,
    event_tx: RwLock<Vec<mpsc::Sender<Arc<Event>>>>,
    run: AtomicBool,
}

#[derive(Clone)]
pub struct Listener {
    inner: Arc<InnerListener>,
}

// Implementing Drop to make the thread stop automatically once the object is dropped.
impl Drop for Listener {
    fn drop(&mut self) {
        self.inner
            .run
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Listener {
    pub fn new(settings: Settings) -> Self {
        let s = Self {
            inner: Arc::new(InnerListener {
                settings,
                event_tx: RwLock::new(vec![]),
                run: AtomicBool::new(true),
            }),
        };

        let s_ref = s.clone();

        std::thread::spawn(move || {
            let _ = s_ref.listen();
        });

        s
    }

    pub fn subscribe(&self) -> mpsc::Receiver<Arc<Event>> {
        let (tx, rx) = mpsc::channel();
        self.inner.event_tx.write().unwrap().push(tx);
        rx
    }

    pub fn is_running(&self) -> bool {
        self.inner.run.load(Ordering::Relaxed)
    }

    fn broadcast(&self, event: Event) {
        let mut tx = self.inner.event_tx.write().unwrap();

        let event = Arc::new(event);

        // Rev is to avoid index shifting
        for i in (0..tx.len()).rev() {
            if tx[i].send(event.clone()).is_err() {
                tx.remove(i);
            }
        }
    }

    fn listen(&self) -> io::Result<()> {
        let (_tx, mut rx) =
            match datalink::channel(&self.inner.settings.interface, Default::default())? {
                Ethernet(tx, rx) => Ok((tx, rx)),
                _ => Err(io::Error::other("Unhandled channel type")),
            }?;

        while self.inner.run.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(packet) => {
                    let events = frame_to_events(packet);

                    for event in events {
                        self.broadcast(event);
                    }
                }
                Err(e) => {
                    eprintln!("Error while receiving from RAW socket: {e}");
                }
            }
        }

        Ok(())
    }
}
