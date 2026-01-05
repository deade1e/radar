use std::{
    fmt::Display,
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
};

use log::error;

use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        ethernet::EthernetPacket,
        ipv4::Ipv4Packet,
        tcp::{TcpFlags, TcpPacket},
        Packet,
    },
};
use serde::Serialize;

use crate::{
    listener::{frame_to_events, Event},
    net::packet::{CanBuild, PacketBuilder, PacketTcp},
    portgrid::scanresults::{IpScanResult, ScanResults},
};

pub mod scanresults;

#[derive(Clone, Copy, Serialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Clone, Copy, Serialize)]
pub enum PortEvent {
    Open {
        ip: Ipv4Addr,
        port: u16,
        proto: Proto,
    },
}

impl Display for PortEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open {
                ip,
                port,
                proto,
                // reason: _,
            } => write!(f, "{ip}:{port}/{proto} is open!"),
        }
    }
}

pub struct PortGrid {
    proto: Proto,

    source_port: u16,

    /// Sequence number to expect syn-acks for. Only used in case of TCP proto
    seq: u32,

    tx: Box<dyn DataLinkSender + 'static>,
    rx: Option<Box<dyn DataLinkReceiver + 'static>>,

    evtx: Vec<Sender<PortEvent>>,
}

impl PortGrid {
    pub fn new(
        iface: NetworkInterface,
        proto: Proto,
        source_port: u16,
        seq: u32,
    ) -> io::Result<Self> {
        let (tx, rx) = match datalink::channel(&iface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => {
                return Err(io::Error::other("Cannot obtain datalink channel"));
            }
        };

        Ok(Self {
            proto,
            source_port,
            seq,
            tx,
            rx: Some(rx),
            evtx: vec![],
        })
    }

    pub fn subscribe(&mut self) -> Receiver<PortEvent> {
        let (tx, rx) = channel();

        self.evtx.push(tx);

        rx
    }

    fn broadcast(&mut self, event: PortEvent) {
        for i in (0..self.evtx.len()).rev() {
            if self.evtx[i].send(event).is_err() {
                self.evtx.remove(i);
            }
        }
    }

    fn reply_rst(&mut self, frame: &[u8]) {
        let eth = EthernetPacket::new(frame).unwrap();
        let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ipv4.payload()).unwrap();

        let mut pb = PacketBuilder::<54>::new(eth.get_destination(), eth.get_source())
            .unwrap()
            .ipv4(ipv4.get_destination(), ipv4.get_source())
            .unwrap()
            .tcp(tcp.get_destination(), tcp.get_source())
            .unwrap()
            .sequence(tcp.get_acknowledgement())
            .flags(TcpFlags::RST);

        let pkt = pb.build();

        self.tx.send_to(pkt, None);
    }

    fn on_open_port(
        &mut self,
        sr: &mut ScanResults,
        ip: Ipv4Addr,
        port: u16,
        proto: Proto,
    ) -> bool {
        match sr.0.get_mut(&ip) {
            None => {
                let mut res = IpScanResult::new();

                res.add_open(port);
                sr.0.insert(ip, res);

                self.broadcast(PortEvent::Open { ip, port, proto });

                return true;
            }
            Some(res) => {
                if res.check_open(port) {
                    // Do nothing
                    return false;
                } else {
                    res.add_open(port);
                    self.broadcast(PortEvent::Open { ip, port, proto });
                    return true;
                }
            }
        }
    }

    pub fn run(mut self, canrun: Arc<AtomicBool>) -> ScanResults {
        let mut results = ScanResults::new();

        // Avoiding perpetual mutable borrow of self by extracting rx
        let mut rx = self.rx.take().expect("RX should be available");

        while canrun.load(Ordering::Relaxed) {
            let frame = match rx.next() {
                Ok(frame) => frame,
                Err(e) => {
                    error!("Error while receiving from RAW socket {e}");
                    continue;
                }
            };

            let events = frame_to_events(frame);

            for event in events {
                match event {
                    Event::SynAck {
                        source_ip,
                        dest_ip: _,
                        source_port,
                        dest_port,
                        ack,
                        packet: _,
                    } if matches!(self.proto, Proto::Tcp)
                        && dest_port == self.source_port
                        && ack == self.seq + 1 =>
                    {
                        let inserted =
                            self.on_open_port(&mut results, source_ip, source_port, Proto::Tcp);

                        if inserted {
                            self.reply_rst(frame);
                        }
                    }
                    Event::Udp {
                        source_ip,
                        dest_ip: _,
                        source_port,
                        dest_port,
                        payload: _,
                    } if matches!(self.proto, Proto::Udp) && dest_port == self.source_port => {
                        let _inserted =
                            self.on_open_port(&mut results, source_ip, source_port, Proto::Udp);
                    }
                    _ => {}
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use crate::portgrid::IpScanResult;

    #[test]
    fn ip_scan_result_near_ranges() {
        let mut isr = IpScanResult::new();

        isr.add_open(21);
        isr.add_open(22);
        isr.add_open(24);
        isr.add_open(25);

        assert!(isr.check_open(23) == false);
    }
}
