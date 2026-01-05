use std::io::IsTerminal;

use crate::radar::Radar;
use hackshell::{Command, CommandResult, Hackshell};

pub struct Arp {
    radar: Radar,
}

impl Arp {
    pub fn new(radar: Radar) -> Self {
        Self { radar }
    }
}

impl Command for Arp {
    fn commands(&self) -> &'static [&'static str] {
        &["arp"]
    }

    fn help(&self) -> &'static str {
        "Shows the ARP table"
    }

    fn run(&self, _s: &Hackshell, _cmd: &[&str]) -> CommandResult {
        let stdout = std::io::stdout();

        let arp_table = self.radar.get_arp_table();

        if stdout.is_terminal() {
            eprintln!("\n{:<24} {:<24}", "IP", "MAC");
            eprintln!("{:<24} {:<24}\n", "--", "---");
        }

        for (ip, entry) in arp_table.read_table().iter() {
            if stdout.is_terminal() {
                // Terminal stdout
                println!("\r{:<24} {:<24}", ip, entry.mac);
            } else {
                // Redirected stdout
                println!("{} at {}", ip, entry.mac);
            }
        }

        Ok(None)
    }
}
