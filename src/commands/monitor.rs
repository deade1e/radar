use std::{io::IsTerminal, sync::atomic::Ordering, time::Duration};

/// Create the monitor module for Radar
use clap::{Parser, ValueEnum};
use hackshell::{Command, CommandResult, Hackshell};
use log::info;

use crate::{listener::Event, net::interface::get_eth_channel, radar::Radar, wait_for_event};

#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum EventType {
    Arp,
    Syn,
    SynAck,
    Udp,
    DhcpReq,
    DhcpDiscover,
}

#[derive(Parser, Debug)]
#[command(name = "monitor", about = "Monitors for incoming packets")]
struct Cmd {
    /// Event filter
    #[clap(short = 'f', long, value_enum)]
    filter: Option<Vec<EventType>>,
}

impl EventType {
    fn shall_pass(filter: &[EventType], e: &Event) -> bool {
        match *e {
            Event::ArpReply { .. } => filter.contains(&EventType::Arp),
            Event::Syn { .. } => filter.contains(&EventType::Syn),
            Event::SynAck { .. } => filter.contains(&EventType::SynAck),
            Event::Udp { .. } => filter.contains(&EventType::Udp),
            Event::DhcpRequest { .. } => filter.contains(&EventType::DhcpReq),
            Event::DhcpDiscover { .. } => filter.contains(&EventType::DhcpDiscover),
        }
    }
}
pub struct Monitor {
    radar: Radar,
}

impl Monitor {
    pub fn new(radar: Radar) -> Self {
        Self { radar }
    }
}

impl Command for Monitor {
    fn commands(&self) -> &'static [&'static str] {
        &["monitor"]
    }

    fn help(&self) -> &'static str {
        "Listens and prints received packets"
    }

    fn run(&self, handler: &Hackshell, cmd: &[&str]) -> CommandResult {
        let args = Cmd::try_parse_from(cmd)?;

        let radar_ref = self.radar.clone();

        handler.spawn("monitor", move |run| {
            let iface = radar_ref.get_iface();
            let (_tx, mut rx) = get_eth_channel(&iface).ok()?;

            while run.load(Ordering::Relaxed) {
                let e = if let Some(ref filter) = args.filter {
                    wait_for_event!(rx, Duration::from_secs(1), ev if EventType::shall_pass(filter, &ev) => ev)
                } else {
                    // TODO: In case of no filters, the first event of a Vec<Event> is taken with
                    // this macro. Fix it.
                    wait_for_event!(rx, Duration::from_secs(1), ev => ev)
                };

                let Some(e) = e else {
                    continue;
                };

                let json = serde_json::to_string(&e).unwrap();

                if std::io::stdout().is_terminal() {
                    // Terminal stdout
                    info!("{json}");
                } else {
                    // Redirected stdout
                    println!("{json}");
                }
            }

            None
        });

        info!("Monitor task spawned");

        Ok(None)
    }
}
