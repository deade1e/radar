#![allow(dead_code)]

use commands::arp::Arp;
use commands::arpscan::ArpScan;
use commands::monitor::Monitor;
use commands::scan::Scan;
use commands::stats::Stats;
use hackshell::error::HackshellError;
use hackshell::Hackshell;
use log::{debug, error, info};
use radar::Radar;

use settings::Settings;

use std::error::Error;
use std::fs::read_to_string;
use std::io::{IsTerminal, Write};
use std::net::Ipv4Addr;
use std::time::Duration;
use std::{path::Path, sync::Arc};

use clap::{Args, Parser, Subcommand};

use crate::net::arp::query::ArpQuery;

mod commands;
mod config;
mod listener;
mod net;
mod portgrid;
mod radar;
mod route_table;
mod scanner;
mod settings;
mod targetiter;

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct RadarArgs {
    /// The network interface
    // Create the clap short and long arguments for the interface. Make the interface argument required.
    #[clap(short, long, required = true)]
    pub interface: String,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Console(ConsoleArgs),
    Scan(commands::scan::Args),
}

#[derive(Debug, Args)]
pub struct ConsoleArgs {
    /// Script to execute
    #[clap(short = 'r', long, value_parser)]
    pub script: Option<String>,
}

struct InnerConsole {
    shell: Hackshell,
}

struct Console {
    inner: Arc<InnerConsole>,
}

impl Clone for Console {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Console {
    fn new(shell: &Hackshell) -> Result<Self, String> {
        Ok(Self {
            inner: Arc::new(InnerConsole {
                shell: shell.clone(),
            }),
        })
    }

    fn read_script(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        for line in read_to_string(path)?.lines() {
            self.inner.shell.feed_line(line)?;
        }

        Ok(())
    }
}

fn interactive_console(console: &Console, args: ConsoleArgs) -> Result<(), Box<dyn Error>> {
    if let Some(script) = args.script {
        console.read_script(Path::new(&script))?;
    }

    let mut stdout = std::io::stdout();

    if stdout.is_terminal() {
        print!("\x1b[2J\x1b[1;1H");
        stdout.flush().unwrap();
    } else {
        info!("Stdout redirection detected, the commands's output will be redirected to stdout");
    }

    loop {
        // Enable the raw mode to catch keypresses
        match console.inner.shell.run() {
            Ok(_) => {}
            Err(e) => {
                if matches!(e, HackshellError::Exit)
                    || matches!(e, HackshellError::Eof)
                    || matches!(e, HackshellError::Interrupted)
                {
                    std::process::exit(0);
                }

                eprintln!("Error: {e}");
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    debug!("Parsing arguments");

    let args = RadarArgs::parse();

    debug!("Getting settings");

    let settings = match args.interface.as_str() {
        "default" => Settings::try_default().unwrap(),
        _ => Settings::by_iface(&args.interface).unwrap(),
    };

    debug!("Instantiating Radar");
    let radar = match Radar::new(settings) {
        Ok(radar) => radar,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };

    debug!("Instantiating Hackshell");
    let shell = Hackshell::new("radar> ")?;

    shell.set_history_file(".radar_history")?;

    debug!("Adding commands");
    shell.add_command(Arp::new(radar.clone()));
    shell.add_command(ArpScan::new(radar.clone()));
    shell.add_command(Monitor::new(radar.clone()));
    shell.add_command(Scan::new(radar.clone()));
    shell.add_command(Stats::new(radar.clone()));

    debug!("Instantiating Console");
    let console = Console::new(&shell)?;

    debug!("Getting router's MAC address");
    let arptable = radar.get_arp_table();
    let iface = radar.get_iface();
    let mut q = ArpQuery::new(&iface, &arptable);
    q.resolve_mac(
        Ipv4Addr::from_octets([1u8, 1, 1, 1]),
        Some(Duration::from_secs(5)),
    );

    debug!("Matching args.command");

    let cmdline_args: Vec<String> = std::env::args().collect();
    let cmdline_refs: Vec<&str> = cmdline_args.iter().map(|s| s.as_str()).collect();

    match args.command {
        Command::Console(args) => {
            interactive_console(&console, args)?;
        }
        Command::Scan(_args) => {
            let start_pos = cmdline_args.iter().position(|s| s == "scan").unwrap();

            match shell.feed_slice(&cmdline_refs.as_slice()[start_pos..]) {
                Ok(_) => {}
                Err(e) => {
                    error!("{e}");
                }
            }

            shell.feed_line("task -w scan_listener").unwrap();
        }
    }

    Ok(())
}
