// Copyright Sebastian Wiesner <sebastian@swsnr.de>

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![deny(warnings, clippy::all, clippy::pedantic,
    // Do cfg(test) right
    clippy::cfg_not_test,
    clippy::tests_outside_test_module,
    // Guard against left-over debugging output
    clippy::dbg_macro,
    clippy::unimplemented,
    clippy::use_debug,
    clippy::todo,
    // Don't panic carelessly
    clippy::get_unwrap,
    clippy::unused_result_ok,
    clippy::unwrap_in_result,
    clippy::indexing_slicing,
    // Do not carelessly ignore errors
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    // Code smells
    clippy::float_cmp_const,
    clippy::string_to_string,
    clippy::if_then_some_else_none,
    clippy::large_include_file,
    // Disable as casts
    clippy::as_conversions,
)]
#![forbid(unsafe_code)]

use std::fmt::Display;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use clap::{ArgAction, Parser, ValueHint, builder::ArgPredicate};
use wol::MacAddr6;

#[derive(Debug)]
struct ResolvedWakeUpTarget {
    hardware_address: MacAddr6,
    socket_addr: SocketAddr,
    secure_on: Option<SecureOn>,
}

#[derive(Debug, Clone, Copy)]
enum ResolveMode {
    Default,
    PreferIpv6,
}

impl Default for ResolveMode {
    fn default() -> Self {
        Self::Default
    }
}

#[derive(Debug)]
struct WakeUpTarget {
    hardware_address: MacAddr6,
    host: Host,
    port: u16,
    secure_on: Option<SecureOn>,
}

impl WakeUpTarget {
    fn resolve(&self, mode: ResolveMode) -> std::io::Result<ResolvedWakeUpTarget> {
        match &self.host {
            Host::Dns(dns) => {
                let mut socket_addrs = (dns.as_str(), self.port).to_socket_addrs()?;
                let socket_addr = match mode {
                    ResolveMode::Default => socket_addrs.next(),
                    ResolveMode::PreferIpv6 => socket_addrs.find(SocketAddr::is_ipv6),
                };
                if let Some(socket_addr) = socket_addr {
                    Ok(ResolvedWakeUpTarget {
                        hardware_address: self.hardware_address,
                        socket_addr,
                        secure_on: self.secure_on,
                    })
                } else {
                    Err(std::io::Error::new(
                        ErrorKind::HostUnreachable,
                        format!("Host {dns} not reachable"),
                    ))
                }
            }
            Host::Ip(ip_addr) => Ok(ResolvedWakeUpTarget {
                hardware_address: self.hardware_address,
                socket_addr: SocketAddr::new(*ip_addr, self.port),
                secure_on: self.secure_on,
            }),
        }
    }
}

#[derive(Debug, Clone)]
enum Host {
    Dns(String),
    Ip(IpAddr),
}

impl Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Dns(dns) => write!(f, "{dns}"),
            Host::Ip(ip_addr) => write!(f, "{ip_addr}"),
        }
    }
}

impl From<String> for Host {
    fn from(value: String) -> Self {
        Ipv4Addr::from_str(&value)
            .map(IpAddr::from)
            .ok()
            .or_else(|| Ipv6Addr::from_str(&value).ok().map(IpAddr::from))
            .map_or_else(|| Self::Dns(value), Self::Ip)
    }
}

#[derive(Debug, Copy, Clone)]
struct SecureOn([u8; 6]);

impl From<SecureOn> for [u8; 6] {
    fn from(value: SecureOn) -> Self {
        value.0
    }
}

impl FromStr for SecureOn {
    type Err = macaddr::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We conveniently reuse the MAC address parser, because the SecureON
        // sequence is just the same length as a MAC address.  Since we now that
        // there are six bytes inside the MacAdd6 we can safely unwrap here.
        MacAddr6::from_str(s).map(MacAddr6::into_array).map(Self)
    }
}

const AFTER_HELP: &str = "Copyright (C) Sebastian Wiesner <sebastian@swsnr.de>
https://github.com/swsnr/wol.rs

This program is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.";

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about,
    disable_help_flag = true,

    after_help = AFTER_HELP
)]
#[group()]
struct CliArgs {
    /// Show this help message.
    #[arg(short = '?', long = "help", action = ArgAction::Help)]
    help: (),
    /// Send the magic packet to HOST.
    ///
    /// HOST may either be a DNS name, or an IPv4/IPv6 address.
    /// HOST may and most likely will be different from the
    /// target system to wake up: Instead the magic packet needs
    /// to be sent so that it physically passes the system to
    /// wake up.  As such, you will most likely want to use a
    /// broadcast or multicast address here.
    ///
    /// Defaults to the IPv4 broadcast address 255.255.255.255
    /// or the IPv6 `ff02::1`, if --ipv6 is given.
    #[arg(
        short = 'h',
        long = "host",
        visible_short_alias = 'i',
        visible_alias = "ipaddr",
        default_value = "255.255.255.255",
        default_value_if("ipv6", ArgPredicate::IsPresent, Some("ff02::1")),
        verbatim_doc_comment
    )]
    host: Host,
    /// Prefer IPv6 addresses over IPv4 for DNS resolution.
    ///
    /// This only affects DNS resolution for hostnames
    /// given to --host; literal IPv4 and IPv6 addresses will
    /// always use the respective protocol.
    ///
    /// If omitted use the first resolved address returned
    /// by the operating system, regardless of whether it is
    /// an IPv4 or IPv6 address.
    #[arg(short = '6', long = "ipv6")]
    ipv6: bool,
    /// Send the magic packet to PORT.
    #[arg(
        short = 'p',
        long = "port",
        default_value = "40000",
        verbatim_doc_comment
    )]
    port: u16,
    /// Read systems to wake up from FILE.
    ///
    /// Read lines of hardware address, and (optionally) IP
    /// addresses/hostnames, ports, and SecureON passwords from
    /// FILE, or stdin, if FILE is -.
    ///
    /// Fields in each line are separated by one or more spaces
    /// or tabs; for each missing field the value of the
    /// corresponding option or the global default will be used.
    #[arg(short = 'f', long = "file", value_hint = ValueHint::FilePath)]
    file: Option<PathBuf>,
    /// Verbose output.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// Wait after each magic packet.
    ///
    /// After each magic packet wait for the given number of
    /// milliseconds; use this to avoid waking up too many
    /// systems too fast.
    #[arg(
        short = 'w',
        long = "wait",
        value_name = "MSECS",
        value_parser = |v: &str| u64::from_str(v).map(Duration::from_millis),
        verbatim_doc_comment
    )]
    wait: Option<Duration>,
    /// Include the given SecureON password in the magic packet.
    ///
    /// The password is in the same format as a MAC address, i.e.
    /// XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX.
    #[arg(long = "passwd")]
    passwd: Option<SecureOn>,
    /// Hardware addresses to wake up.
    #[arg(
        value_name = "MAC-ADDRESS",
        required_unless_present("file"),
        verbatim_doc_comment
    )]
    hardware_addresses: Vec<wol::MacAddr6>,
}

impl CliArgs {
    fn targets(&self) -> impl Iterator<Item = WakeUpTarget> {
        self.hardware_addresses
            .iter()
            .map(move |hardware_address| WakeUpTarget {
                hardware_address: *hardware_address,
                host: self.host.clone(),
                port: self.port,
                secure_on: self.passwd,
            })
    }

    fn resolve_mode(&self) -> ResolveMode {
        if self.ipv6 {
            ResolveMode::PreferIpv6
        } else {
            ResolveMode::Default
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    version,
    about,
    disable_help_flag = true,

    after_help = AFTER_HELP
)]
struct Cli {
    #[clap(flatten)]
    args: CliArgs,
    /// Print manpage and exit.
    #[cfg(feature = "manpage")]
    #[arg(long = "print-manpage", exclusive = true)]
    manpage: bool,
    /// Print completions for SHELL and exit
    #[cfg(feature = "completions")]
    #[arg(long = "print-completions", exclusive = true)]
    completions: Option<clap_complete::Shell>,
}

fn wakeup(target: &WakeUpTarget, mode: ResolveMode, verbose: bool) -> std::io::Result<()> {
    if verbose {
        println!(
            "Waking up {} with {}:{}...",
            target.hardware_address, target.host, target.port
        );
    } else {
        println!("Waking up {}...", target.hardware_address);
    }
    let target = target.resolve(mode)?;
    wol::send_magic_packet(
        target.hardware_address,
        target.secure_on.map(Into::into),
        target.socket_addr,
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    #[cfg(feature = "manpage")]
    if cli.manpage {
        use clap::CommandFactory;
        let manpage = clap_mangen::Man::new(CliArgs::command());
        if let Err(error) = manpage.render(&mut std::io::stdout()) {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    #[cfg(feature = "completions")]
    if let Some(shell) = cli.completions {
        use clap::CommandFactory;
        clap_complete::generate(
            shell,
            &mut CliArgs::command(),
            "wol",
            &mut std::io::stdout(),
        );
    }

    let args = cli.args;
    #[allow(clippy::todo)]
    if args.file.is_some() {
        todo!("Wakeup files");
    }

    let resolve_mode = args.resolve_mode();
    let mut return_code = ExitCode::SUCCESS;
    for (i, target) in args.targets().enumerate() {
        if 0 < i {
            if let Some(wait) = args.wait.filter(|d| !d.is_zero()) {
                sleep(wait);
            }
        }
        if let Err(error) = wakeup(&target, resolve_mode, args.verbose) {
            eprintln!("Failed to wake up {}: {error}", target.hardware_address);
            return_code = ExitCode::FAILURE;
        }
    }
    return_code
}
