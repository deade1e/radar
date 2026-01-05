//! The scanner module spits TCP and UDP packets as fast as possible.
//! It doesn't handle the reply packets as it would need to attach to the radar instance and print
//! messages, which is not something we want.
//! Reply packets are handled by PortGrid.
//! It makes use both of Radar APIs indirectly and pnet APis directly.
//! Gets instantiated by scan command under commands/scan.rs.

use std::io::{self};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{collections::HashMap, net::Ipv4Addr};

use log::debug;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use pnet::ipnetwork::Ipv4Network;
use pnet::packet::tcp::{TcpFlags, TcpOption};
use pnet::util::MacAddr;
use rand::Rng;

use crate::net::interface::get_eth_channel;
use crate::net::packet::{PacketBuilder, PacketIpv4};
use crate::net::packet::{CanBuild, HasPorts, PacketTcp};
use crate::portgrid::{self, scanresults::ScanResults, PortEvent, PortGrid};
use crate::targetiter::TargetIter;

const PACKET_LEN: usize = 1024;
const MIN_UDP_PACKET_LEN: usize = 42;

#[derive(derive_builder::Builder)]
pub struct ScannerConfig {
    /// Network interface to use for the scan
    iface: NetworkInterface,

    /// Subnet to scan
    subnet: Ipv4Network,

    /// Port range
    ports: RangeInclusive<u16>,

    /// UDP or TCP
    udp: bool,

    /// MAC Address of the router to be used. If None gets detected automatically.
    router_mac: Option<MacAddr>,

    /// ARP Mode scanning. If true only scans IP addresses in ARP table.
    arp_mode: bool,

    /// Callback function to be called to obtain a possible MacAddr for a specific Ipv4Addr
    #[builder(setter(custom))]
    get_mac_addr: Arc<dyn Fn(Ipv4Addr) -> Option<MacAddr> + Send + Sync + 'static>,

    /// Maximum packets per second to send.
    max_rate: usize,

    /// Content to send with each packet. Only used for UDP.
    #[builder(setter(custom))]
    payload: Vec<u8>,

    /// Blacklist of IPs to avoid.
    blacklist: HashMap<Ipv4Addr, bool>,
}

impl ScannerConfigBuilder {
    pub fn get_mac_addr<F>(&mut self, get_mac_addr: F) -> &mut Self
    where
        F: Fn(Ipv4Addr) -> Option<MacAddr> + Send + Sync + 'static,
    {
        self.get_mac_addr = Some(Arc::new(get_mac_addr));
        self
    }

    pub fn payload(&mut self, payload: &[u8]) -> io::Result<&mut Self> {
        if payload.len() > PACKET_LEN - MIN_UDP_PACKET_LEN {
            return Err(io::Error::other("UDP Payload too big"));
        }

        self.payload = Some(payload.to_vec());

        Ok(self)
    }
}

pub struct Scanner {
    config: ScannerConfig,
    source_port: u16,
    seq: u32,
    pub pg: Option<PortGrid>,
}

impl Scanner {
    pub fn new(config: ScannerConfig) -> io::Result<Self> {
        let proto = match config.udp {
            true => portgrid::Proto::Udp,
            false => portgrid::Proto::Tcp,
        };

        let source_port = rand::thread_rng().gen_range(32768..65535);
        let seq: u32 = rand::random();
        let iface = config.iface.clone();

        Ok(Self {
            config,
            source_port,
            seq,
            pg: Some(PortGrid::new(iface, proto, source_port, seq)?),
        })
    }

    pub fn subscribe(&mut self) -> Receiver<PortEvent> {
        self.pg.as_mut().unwrap().subscribe()
    }

    pub fn get_iface_ip(&self) -> io::Result<Ipv4Addr> {
        match self.config.iface.ips[0] {
            IpNetwork::V4(ipv4) => Ok(ipv4.ip()),
            _ => Err(io::Error::other("Can't get interface's IPv4 address")),
        }
    }

    fn scan<T: PacketIpv4 + HasPorts + CanBuild>(
        &mut self,
        pb: T,
        canrun: &Arc<AtomicBool>,
    ) -> io::Result<()> {
        let (mut tx, _rx) = get_eth_channel(&self.config.iface)?;

        let bucket = Arc::new(AtomicUsize::new(0));

        // Setting up bucket algorithm to limit outgoing packets
        if self.config.max_rate > 0 {
            let bucket_ref = bucket.clone();
            let canrun_ref = canrun.clone();
            let rate = self.config.max_rate;

            // Thread to load bucket with tokens later used to send packets
            std::thread::spawn(move || {
                while canrun_ref.load(Ordering::SeqCst) {
                    sleep(Duration::from_millis(1));
                    bucket_ref.fetch_add(rate / 10, Ordering::SeqCst);
                }
            });
        }

        let tl = TargetIter::new(self.config.subnet, self.config.ports.clone());

        for target in tl {
            let mut pb = pb.clone();

            if !canrun.load(Ordering::SeqCst) {
                break;
            }

            if self.config.blacklist.contains_key(&target.ip) {
                continue;
            }

            let mut target_mac = self.config.router_mac.unwrap();

            if self.config.arp_mode {
                if let Some(mac) = (self.config.get_mac_addr)(target.ip) {
                    target_mac = mac;
                } else {
                    continue;
                }
            }

            pb = pb.dest_mac(target_mac);
            pb = pb.destination_ip(target.ip);

            pb = pb.dest_port(target.port);

            if self.config.max_rate > 0 {
                // Wait for bucket reloading
                while bucket.load(Ordering::SeqCst) < 100 {
                    sleep(Duration::from_millis(1));
                }

                // Used 100 tokens, decrementing them.
                bucket.fetch_sub(100, Ordering::SeqCst);
            }

            tx.send_to(pb.build(), None);
        }
        Ok(())
    }

    pub fn run(mut self, canrun: Arc<AtomicBool>) -> io::Result<ScanResults> {
        let source_mac = self.config.iface.mac.unwrap();
        let source_ip = self.get_iface_ip()?;

        let canrun_ref = canrun.clone();
        let pg = self.pg.take().unwrap();

        let pg_handle = std::thread::spawn(move || pg.run(canrun_ref));

        let pb = PacketBuilder::<PACKET_LEN>::new(source_mac, source_mac)
            .unwrap()
            .ipv4(source_ip, source_ip)
            .unwrap();

        if !self.config.udp {
            let pb = pb
                .tcp(self.source_port, self.source_port)
                .unwrap()
                .sequence(self.seq)
                .acknowledgement(0)
                .flags(TcpFlags::SYN)
                .window(1024);

            let pb = pb.options(&[TcpOption::mss(1460)]).unwrap();

            self.scan(pb, &canrun)?;
        } else {
            let pb = pb
                .udp(self.source_port, self.source_port)
                .unwrap()
                .payload(&self.config.payload)
                .unwrap();

            self.scan(pb, &canrun)?;
        }

        debug!("Waiting 10 seconds for remaining packets...");
        sleep(Duration::from_secs(10));
        // Setting canrun to false manually so that PortGrid's thread finishes
        canrun.store(false, Ordering::Relaxed);

        match pg_handle.join() {
            Ok(results) => Ok(results),
            Err(e) => {
                if let Some(e) = e.downcast_ref::<&str>() {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("PortGrid thread returned error: {e}"),
                    ))
                } else if let Some(e) = e.downcast_ref::<String>() {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("PortGrid thread returned error: {e}"),
                    ))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("PortGrid thread returned non printable error"),
                    ))
                }
            }
        }
    }
}
