// Copyright Sebastian Wiesner <sebastian@swsnr.de>

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// #![deny(warnings, clippy::all, clippy::pedantic,
//     // Do cfg(test) right
//     clippy::cfg_not_test,
//     clippy::tests_outside_test_module,
//     // Guard against left-over debugging output
//     clippy::dbg_macro,
//     clippy::unimplemented,
//     clippy::use_debug,
//     clippy::todo,
//     // Require correct safety docs
//     clippy::undocumented_unsafe_blocks,
//     clippy::unnecessary_safety_comment,
//     clippy::unnecessary_safety_doc,
//     // We must use Gtk's APIs to exit the app.
//     clippy::exit,
//     // Don't panic carelessly
//     clippy::get_unwrap,
//     clippy::unused_result_ok,
//     clippy::unwrap_in_result,
//     clippy::indexing_slicing,
//     // Do not carelessly ignore errors
//     clippy::let_underscore_must_use,
//     clippy::let_underscore_untyped,
//     // Code smells
//     clippy::float_cmp_const,
//     clippy::string_to_string,
//     clippy::if_then_some_else_none,
//     clippy::large_include_file,
//     // Disable as casts
//     clippy::as_conversions,
// )]

use std::{
    fmt::Display,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    thread::sleep,
    time::Duration,
};

use clap::{ArgAction, Parser, ValueHint, builder::ArgPredicate};
use wol::{MacAddr6, SendMagicPacket};

#[derive(Debug)]
struct ResolvedWakeUpTarget {
    hardware_address: MacAddr6,
    socket_addr: SocketAddr,
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
}

impl WakeUpTarget {
    fn resolve(&self, mode: ResolveMode) -> std::io::Result<ResolvedWakeUpTarget> {
        match &self.host {
            Host::Dns(dns) => {
                let mut socket_addrs = (dns.as_str(), self.port).to_socket_addrs()?;
                let socket_addr = match mode {
                    ResolveMode::Default => socket_addrs.next(),
                    ResolveMode::PreferIpv6 => socket_addrs.find(|addr| addr.is_ipv6()),
                };
                if let Some(socket_addr) = socket_addr {
                    Ok(ResolvedWakeUpTarget {
                        hardware_address: self.hardware_address,
                        socket_addr,
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

#[derive(Parser, Debug)]
#[command(version, about, disable_help_flag = true)]
struct CliArgs {
    /// Show this help message.
    #[arg(short = '?', long = "help", action = ArgAction::Help)]
    help: (),
    /// Send the magic packet to this IP address or hostname.
    ///
    /// Defaults to the IPv4 broadcast address `255.255.255.255` or the IPv6
    /// `ff02::1`.
    #[arg(
        short = 'h',
        long = "host",
        visible_short_alias = 'i',
        visible_alias = "ipaddr",
        default_value = "255.255.255.255",
        default_value_if("ipv6", ArgPredicate::IsPresent, Some("ff02::1"))
    )]
    host: Host,
    /// Prefer IPv6 addresses over IPv4 for DNS resolution.
    ///
    /// This only affects DNS resolution for hostnames given to --host; literal
    /// IPv4 and IPv6 addresses will always use the respective protocol.
    ///
    /// If omitted use the first resolved address returned by the operating system,
    /// regardless of whether it is an IPv4 or IPv6 address.
    #[arg(short = '6', long = "ipv6")]
    ipv6: bool,
    /// Send the magic packet to this port instead of the default.
    #[arg(short = 'p', long = "port", default_value = "40000")]
    port: u16,
    /// Read lines of hardware addresses, and (optionally) IP addresses/hostnames, ports, and SecureON passwords from
    /// the given file, or stdin, if `-` was given.
    #[arg(short = 'f', long = "file", value_hint = ValueHint::FilePath)]
    file: Option<PathBuf>,
    /// Verbose output.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// Wait for given number of milliseconds after each magic packet.
    #[arg(
        short = 'w',
        long = "wait",
        value_name = "MSECS",
        value_parser = |v: &str| u64::from_str(v).map(Duration::from_millis)
    )]
    wait: Option<Duration>,
    /// Include the given SecureON password in the magic packet.
    ///
    /// If the password is omitted, prompt for the password.
    #[arg(long = "passwd")]
    passwd: Option<Option<String>>,
    /// Hardware addresses to wake up.
    #[arg(value_name = "MAC-ADDRESS", required_unless_present("file"))]
    hardware_addresses: Vec<wol::MacAddr6>,
}

impl CliArgs {
    fn targets(&self) -> impl Iterator<Item = WakeUpTarget> {
        self.hardware_addresses
            .iter()
            .map(|hardware_address| WakeUpTarget {
                hardware_address: *hardware_address,
                host: self.host.clone(),
                port: self.port,
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

fn wakeup(target: &WakeUpTarget, mode: ResolveMode, verbose: bool) -> std::io::Result<()> {
    if verbose {
        println!(
            "Waking up {} with {}:{}...",
            target.hardware_address, target.host, target.port
        );
    } else {
        println!("Waking up {}...", target.hardware_address)
    }
    let target = target.resolve(mode)?;
    let bind_address = if target.socket_addr.is_ipv6() {
        IpAddr::from(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    };
    let socket = UdpSocket::bind((bind_address, 0))?;
    socket.send_magic_packet(target.hardware_address, target.socket_addr)
}

fn main() -> ExitCode {
    let args = CliArgs::parse();
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
