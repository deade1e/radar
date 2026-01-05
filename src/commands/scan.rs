use std::{
    collections::HashMap, error::Error, io::IsTerminal, net::Ipv4Addr, ops::RangeInclusive,
    path::Path, sync::atomic::Ordering,
};

use crate::{
    net::arp::query::ArpQuery,
    radar::Radar,
    scanner::{Scanner, ScannerConfigBuilder},
};

use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use hackshell::{taskpool::TaskOutput, Command, CommandResult, Hackshell};
use ipnetwork::{IpNetwork, Ipv4Network};
use log::{error, info, warn};
use pnet::util::MacAddr;

#[derive(Parser, Debug)]
#[command(name = "scan", about = "Scan the network")]
pub struct Args {
    /// The subnet to scan
    subnet: String,

    /// The ports to scan
    #[clap(short = 'p', required = true)]
    ports: String,

    /// Use UDP instead of TCP
    #[clap(short = 'u', long)]
    udp: bool,

    /// Enables ARP mode for scanning only the local network.
    /// When this option is enabled the packets are sent directly to the target MAC address instead of the router MAC address.
    /// An ARP scan will be performed before the actual port scan while using this option.
    #[clap(short = 'a', long)]
    arp_mode: bool,

    /// The maximum rate of packets to send per second. Default = 1000.
    #[clap(short = 'r', long, value_parser)]
    max_rate: Option<usize>,

    /// JSON output
    #[clap(short = 'j', long)]
    json: bool,

    /// Include response packet content in the JSON output.
    #[clap(long)]
    json_content: bool,

    /// Blacklist file of subnets not to be scanned or ever contacted in any way.
    /// Mandatory when a /0 (global IPv4) scan is performed.
    #[clap(short = 'b', long)]
    blacklist: Option<String>,

    /// Router MAC address. Used when the router cannot be detected automatically or for benchmarking purposes.
    #[clap(short = 'm', long)]
    router_mac: Option<MacAddr>,

    /// The content of the packet to send. Must be a base64 encoded string. Only used in UDP mode.
    #[clap(short = 'c', long)]
    content: Option<String>,
}

#[derive(Clone)]
pub struct Scan {
    radar: Radar,
}

impl Scan {
    pub fn new(radar: Radar) -> Self {
        Self { radar }
    }

    fn is_subnet_of(network: IpNetwork, subnet: IpNetwork) -> bool {
        match (subnet, network) {
            (IpNetwork::V4(subnet_v4), IpNetwork::V4(network_v4)) => {
                subnet_v4.network() & network_v4.mask() == network_v4.network()
            }
            (IpNetwork::V6(subnet_v6), IpNetwork::V6(network_v6)) => {
                subnet_v6.network() & network_v6.mask() == network_v6.network()
            }
            _ => false, // Can't compare IPv4 with IPv6
        }
    }

    pub fn parse_port_range(input: &str) -> Result<RangeInclusive<u16>, String> {
        let parts: Vec<&str> = input.split('-').collect();

        match parts.len() {
            1 => {
                // Only one value, create a range of that number
                if let Ok(value) = parts[0].parse::<u16>() {
                    return Ok(value..=value);
                }
            }
            2 => {
                // Two values, create a range from start to end
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    return Ok(start..=end);
                }
            }
            _ => {}
        }

        Err("Cannot parse range".to_string())
    }

    pub fn read_blacklist(
        path: &Path,
    ) -> Result<HashMap<Ipv4Addr, bool>, Box<dyn Error + Send + Sync + 'static>> {
        if !path.exists() {
            return Err("Blacklist file does not exist".into());
        }

        let contents = std::fs::read_to_string(path)?;
        let mut blacklist = HashMap::new();

        for line in contents.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            if line.contains('-') {
                let parts: Vec<&str> = line.split('-').collect();
                let start = parts[0].parse::<Ipv4Addr>()?;
                let end = parts[1].parse::<Ipv4Addr>()?;
                for ip in start..=end {
                    blacklist.insert(ip, true);
                }
            } else if line.contains('/') {
                let subnet: Ipv4Network = line.parse()?;
                for ip in subnet.iter() {
                    blacklist.insert(ip, true);
                }
            } else {
                let ip = line.parse::<Ipv4Addr>()?;
                blacklist.insert(ip, true);
            }
        }

        Ok(blacklist)
    }
}

impl Command for Scan {
    fn commands(&self) -> &'static [&'static str] {
        &["scan"]
    }

    fn help(&self) -> &'static str {
        "Main command. Lots of stuff"
    }

    fn run(&self, handler: &Hackshell, cmd: &[&str]) -> CommandResult {
        let args = Args::try_parse_from(cmd)?;

        let subnet: Ipv4Network = args.subnet.parse()?;
        let port_range = Self::parse_port_range(args.ports.as_str())?;
        let udp = args.udp;
        let arp_mode = args.arp_mode;
        let max_rate: usize = args.max_rate.unwrap_or(1000);

        let json_output = args.json;
        let _json_content = args.json_content;
        let router_mac = args.router_mac;

        // kOQBAAABAAAAAAABBmdvb2dsZQNjb20AAAEAAQAAKQSwAAAAAAAA
        // This is a standard DNS query packet content for google.com
        let content = args.content;

        if subnet.prefix() == 0 {
            warn!("Scanning the entire internet is not recommended");
            warn!("This will take a long time and may be illegal in your jurisdiction");
            warn!("Consider using a smaller subnet or a specific IP address");
            warn!("You have been warned");

            if args.blacklist.is_none() {
                return Err(
                    "Specify a blacklist, even an empty file, when scanning the entire IPv4 range."
                        .into(),
                );
            }
        }

        let blacklist = match args.blacklist {
            Some(path) => Self::read_blacklist(path.as_ref())?,
            None => HashMap::new(),
        };

        // Here start the actual implementation of the module
        // Starting the two tasks for listening and sending packets

        if arp_mode {
            let mut found = false;

            for isubnet in self.radar.get_iface_subnets() {
                if Self::is_subnet_of(isubnet, subnet.into()) {
                    found = true;
                    break;
                }
            }

            if !found {
                return Err("The subnet is not part of the interface subnets".into());
            }

            handler.feed_line(format!("arpscan -s {subnet}").as_str())?;
            let _ = handler.join("arp_listener");
        }

        let radar_ref = self.radar.clone();
        let handler_ref = handler.clone();

        info!("Launching SYN scan on subnet: {subnet}");

        let arptable = radar_ref.get_arp_table();
        let iface = radar_ref.get_iface();
        let mut q = ArpQuery::new(&iface, &arptable);

        let router_mac = match router_mac {
            Some(mac) => mac,
            None => q
                .resolve_mac(Ipv4Addr::from_octets([1u8, 1, 1, 1]), None)
                .unwrap(),
        };

        let content = match &content {
            Some(content) => BASE64_STANDARD.decode(content.as_bytes()).unwrap(),
            None => vec![],
        };

        let config = ScannerConfigBuilder::default()
            .iface(radar_ref.get_iface())
            .subnet(subnet)
            .ports(port_range)
            .max_rate(max_rate)
            .udp(udp)
            .arp_mode(arp_mode)
            .router_mac(Some(router_mac))
            .blacklist(blacklist)
            .payload(&content)?
            .get_mac_addr(move |ip| arptable.get(ip).map(|e| e.mac))
            .build()
            .unwrap();

        let mut scanner = match Scanner::new(config) {
            Ok(scanner) => scanner,
            Err(e) => {
                error!("{}", e);
                return Ok(None);
            }
        };

        // Subscribing to PortGrid event channel
        let rx = scanner.subscribe();

        handler.spawn("scan_listener", move |run| {
            while run.load(Ordering::Relaxed) {
                if let Ok(event) = rx.recv() {
                    if json_output {
                        if std::io::stdout().is_terminal() {
                            info!("{}", serde_json::to_string(&event).unwrap());
                        } else {
                            println!("{}", serde_json::to_string(&event).unwrap());
                        }
                    } else {
                        info!("{}", event);
                    }
                }
            }

            None
        });

        handler.spawn("scan", move |run| {
            let ret = scanner.run(run);

            let results = match ret {
                Ok(results) => {
                    // let results_json = serde_json::to_string(&results).unwrap();
                    // Forcing type erasure
                    let erased: TaskOutput = Some(Box::new(results));
                    erased
                }
                Err(e) => {
                    error!("{e}");
                    None
                }
            };

            let _ = handler_ref.terminate("scan_listener");
            info!("Scan terminated.");
            results
        });

        Ok(None)
    }
}
