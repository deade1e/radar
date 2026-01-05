use std::{io::IsTerminal, sync::atomic::Ordering, thread::sleep, time::Duration};

use crate::{
    listener::{self},
    net::{arp::query::ArpQuery, interface::get_eth_channel},
    radar::Radar, wait_for_event,
};

use clap::Parser;
use hackshell::{Command, CommandResult, Hackshell};
use ipnetwork::{IpNetwork::V4, Ipv4Network};
use log::info;
use serde::Serialize;

#[derive(Parser)]
struct Cmd {
    /// Subnet to scan
    #[clap(short = 's', long)]
    pub subnet: Option<String>,

    /// All subnets of the interface
    #[clap(short = 'a', long)]
    pub all: bool,

    /// JSON output
    #[clap(short = 'j', long)]
    pub json: bool,
}

#[derive(Serialize)]
pub struct ArpScanResult {
    pub ip: String,
    pub mac: String,
}

pub struct ArpScan {
    radar: Radar,
}

impl ArpScan {
    pub fn new(radar: Radar) -> Self {
        Self { radar }
    }
}

impl Command for ArpScan {
    fn commands(&self) -> &'static [&'static str] {
        &["arpscan"]
    }

    fn help(&self) -> &'static str {
        "Launches a ARP scan"
    }

    fn run(&self, handler: &Hackshell, cmd: &[&str]) -> CommandResult {
        let args = Cmd::try_parse_from(cmd)?;
        let mut subnets: Vec<Ipv4Network> = Vec::new();
        let iface = self.radar.get_iface();
        let arptable = self.radar.get_arp_table();

        let json_output = args.json;

        match args {
            Cmd {
                subnet: Some(subnet),
                all: false,
                json: _,
            } => {
                subnets.push(subnet.parse()?);
            }
            Cmd {
                subnet: None,
                all: true,
                json: _,
            } => {
                for subnet in &iface.ips {
                    if let V4(subnet) = subnet {
                        subnets.push(*subnet);
                    }
                }
            }
            _ => {
                return Err("Specify either a subnet or all subnets".into());
            }
        }

        info!("Launching ARP scan on {} subnets", subnets.len());

        let iface_ref = iface.clone();

        handler.spawn("arp_listener", move |run| {
            let (_tx, mut rx) = get_eth_channel(&iface_ref).ok()?;

            while run.load(Ordering::Relaxed) {
                let r = wait_for_event!(rx, Duration::from_secs(1), listener::Event::ArpReply { ip, mac } => (ip, mac) );
                let Some((ip, mac)) = r else {
                    continue;
                };
                
                let output = match json_output {
                    true => serde_json::to_string(&ArpScanResult {
                        ip: ip.to_string(),
                        mac: mac.to_string(),
                    })
                    .unwrap(),
                    false => format!("{ip:<15} {mac}"),
                };

                if std::io::stdout().is_terminal() {
                    // Terminal stdout
                    info!("{output}");
                } else {
                    // Redirected stdout
                    println!("{output}");
                }
            }

            None
        });

        let handler_ref = handler.clone();

        handler.spawn("arpscan", move |_run| {
            let mut q = ArpQuery::new(&iface, &arptable);

            for subnet in subnets.iter() {
                for ip in subnet.iter() {
                    q.resolve_mac(ip, None);
                    sleep(Duration::from_millis(1));
                }
            }

            sleep(Duration::from_secs(3));

            info!("ARP Scan terminated");

            let _ = handler_ref.terminate("arp_listener");
            None
        });

        Ok(None)
    }
}
