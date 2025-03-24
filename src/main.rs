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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use clap::{ArgAction, Parser, ValueHint, builder::ArgPredicate};
use wol::MacAddr6;

#[derive(Debug, Clone)]
enum Host {
    Dns(String),
    Ip(IpAddr),
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
    /// Send the magic packet with IPv6 instead of IPv4.
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
    ///
    /// If `0` do not wait, but send packets sequentially.  If omitted, send all packets at once.
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

fn main() {
    let args = CliArgs::parse();
    dbg!(args);
}
