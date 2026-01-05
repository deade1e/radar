use hackshell::{Command, CommandResult, Hackshell};
use log::info;

use crate::radar::Radar;

pub struct Stats {
    radar: Radar,
}

impl Stats {
    pub fn new(radar: Radar) -> Self {
        Self { radar }
    }
}

impl Command for Stats {
    fn commands(&self) -> &'static [&'static str] {
        &["stats"]
    }

    fn help(&self) -> &'static str {
        "Shows statistics about packets"
    }

    fn run(&self, _s: &Hackshell, _cmd: &[&str]) -> CommandResult {
        let stats = self.radar.get_stats();

        info!("Total sent packets: {}", stats.sent);
        info!("Total received packets: {}", stats.received);
        info!("Total dropped packets: {}", stats.dropped);
        info!("Packets per second: ~ {}", stats.pps);

        Ok(None)
    }
}
