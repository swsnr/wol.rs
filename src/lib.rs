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
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unimplemented,
    clippy::use_debug,
    clippy::todo,
    // Require correct safety docs
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    // We should not exit here
    clippy::exit,
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
#![allow(clippy::enum_glob_use, clippy::module_name_repetitions)]

//! Wake on LAN magic packets.
//!
//! ## Send magic packets
//!
//! [`send_magic_packet`] provides a convenience function to send a single packet:
//!
//! ```no_run
//! use std::str::FromStr;
//! use std::net::Ipv4Addr;
//! let mac_address = wol::MacAddr6::from_str("12-13-14-15-16-17").unwrap();
//! wol::send_magic_packet(mac_address, (Ipv4Addr::BROADCAST, 9).into()).unwrap();
//! ```
//!
//! For more control, create the [`std::net::UdpSocket`] yourself:
//!
//! ```no_run
//! use std::str::FromStr;
//! use std::net::{Ipv4Addr, UdpSocket};
//! use wol::SendMagicPacket;
//! let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
//! let mac_address = wol::MacAddr6::from_str("12-13-14-15-16-17").unwrap();
//!
//! socket.send_magic_packet(mac_address, (Ipv4Addr::BROADCAST, 9)).unwrap();
//! ```
//!
//! ## Assemble magic packets
//!
//! To send magic packets over other socket APIs, use [`fill_magic_packet`] or [`write_magic_packet`]
//! to assmble magic packets.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

/// MAC address types.
pub use macaddr;
pub use macaddr::MacAddr6;

/// Fill the given `buffer` with the magic packet for the given `mac_address`.
pub fn fill_magic_packet(buffer: &mut [u8; 102], mac_address: MacAddr6) {
    buffer[0..6].copy_from_slice(&[0xff; 6]);
    for i in 0..16 {
        let base = (i + 1) * 6;
        // We know that `buffer` is large enough.
        #[allow(clippy::indexing_slicing)]
        buffer[base..base + 6].copy_from_slice(mac_address.as_bytes());
    }
}

/// Write a magic packet for the given `mac_address` to `sink`.
///
/// # Errors
///
/// Return an error if the underlying [`Write::write_all`] fails.
pub fn write_magic_packet<W: Write>(sink: &mut W, mac_address: MacAddr6) -> std::io::Result<()> {
    sink.write_all(&[0xff; 6])?;
    for _ in 0..16 {
        sink.write_all(mac_address.as_bytes())?;
    }
    Ok(())
}

pub trait SendMagicPacket {
    /// Send a magic packet for `mac_address` to `addr` over this socket.
    ///
    /// # Target address
    ///
    /// Normally, you would send the packet to the broadcast address (IPv4) or
    /// the link-local multicast address (IPv6), but you may specify any address
    /// as long as the target host will *physically see* the packet along its
    /// way to the target address.
    ///
    /// Any target port will do, since the magic packet never makes it to the
    /// operating system where ports matter; the NIC will directly process it.
    ///
    /// Port `9` (discard) is often a good choice, because no service will
    /// listen on this port.
    ///
    /// # Errors
    ///
    /// Return any errors from the underlying socket I/O.
    fn send_magic_packet<A: ToSocketAddrs>(
        &self,
        mac_address: MacAddr6,
        addr: A,
    ) -> std::io::Result<()>;
}

impl SendMagicPacket for UdpSocket {
    fn send_magic_packet<A: ToSocketAddrs>(
        &self,
        mac_address: MacAddr6,
        addr: A,
    ) -> std::io::Result<()> {
        let mut packet = [0; 102];
        fill_magic_packet(&mut packet, mac_address);
        let size = self.send_to(&packet, addr)?;
        // `send_to` won't send partial data until i32::MAX, according to
        // `UdpSocket::send-to`, so if we get a partial write nonetheless
        // something's seriously wrong, and we should just crash for satefy.
        assert!(size == packet.len());
        Ok(())
    }
}

/// Send a magic packet for `mac_address` to `addr`.
///
/// This convenience method binds an UDP socket, and sends a single magic packet
/// for `mac_address` to `addr`.
///
/// To send an magic packet over an existing UDP socket, see [`SendMagicPacket`].
///
/// # Errors
///
/// Return errors from underlying socket I/O.
pub fn send_magic_packet(mac_address: MacAddr6, addr: SocketAddr) -> std::io::Result<()> {
    let bind_address = if addr.is_ipv4() {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::from(Ipv6Addr::UNSPECIFIED)
    };
    let socket = UdpSocket::bind((bind_address, 0))?;
    socket.set_broadcast(true)?;
    socket.send_magic_packet(mac_address, addr)
}

#[cfg(test)]
mod tests {
    use crate::fill_magic_packet;

    use super::{MacAddr6, write_magic_packet};

    #[test]
    fn test_fill_magic_packet() {
        let mac_address = "26:CE:55:A5:C2:33".parse::<MacAddr6>().unwrap();
        let mut buffer = [0; 102];
        fill_magic_packet(&mut buffer, mac_address);
        let expected_packet: [u8; 102] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // // Six all 1 bytes
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, // 16 repetitions of the mac address
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //  5
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, // 10
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, // 15
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
        ];
        assert_eq!(buffer, expected_packet);
    }

    #[test]
    fn test_write_magic_packet() {
        let mac_address = "26:CE:55:A5:C2:33".parse::<MacAddr6>().unwrap();
        let mut buffer = Vec::new();
        write_magic_packet(&mut buffer, mac_address).unwrap();
        let expected_packet: [u8; 102] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // // Six all 1 bytes
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, // 16 repetitions of the mac address
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //  5
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, // 10
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, // 15
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
        ];
        assert_eq!(buffer.as_slice(), expected_packet.as_slice());
    }
}
