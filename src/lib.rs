// Copyright Sebastian Wiesner <sebastian@swsnr.de>

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![deny(warnings,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    clippy::all,
    clippy::pedantic,
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
#![forbid(unsafe_code)]

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
//! wol::send_magic_packet(mac_address, None, (Ipv4Addr::BROADCAST, 9).into()).unwrap();
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
//! socket.send_magic_packet(mac_address, None, (Ipv4Addr::BROADCAST, 9)).unwrap();
//! ```
//!
//! ## Assemble magic packets
//!
//! To send magic packets over other socket APIs, use [`fill_magic_packet`] or [`write_magic_packet`]
//! to assmble magic packets.
//!
//! ## SecureON
//!
//! This crate supports SecureON magic packets.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;

/// MAC address types.
pub use macaddr;
pub use macaddr::MacAddr6;

pub mod file;

/// A SecureON token.
///
/// A SecureON token consists of six bytes, similar to a MAC address.
///
/// If such a SecureON token is set in the firmware of the target device, the
/// device will only wake up if the magic packet additionally includes the given
/// SecureON token.
///
/// This offers a marginal amount of protection against unauthorized wake-ups in
/// case the MAC address of the target device is known. Note however that this
/// SecureON token is included in the magic packet as plain text, so it should
/// **not be assumed a secret**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureOn([u8; 6]);

impl AsRef<[u8]> for SecureOn {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<SecureOn> for [u8; 6] {
    fn from(value: SecureOn) -> Self {
        value.0
    }
}

impl From<[u8; 6]> for SecureOn {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl FromStr for SecureOn {
    type Err = macaddr::ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // We conveniently reuse the MAC address parser, because the SecureON
        // token is just the same length as a MAC address.
        MacAddr6::from_str(s).map(MacAddr6::into_array).map(Self)
    }
}

/// Fill a buffer with a magic packet.
///
/// Fill `buffer` with a magic packet to wake up `mac_address`.
pub fn fill_magic_packet(buffer: &mut [u8; 102], mac_address: MacAddr6) {
    buffer[0..6].copy_from_slice(&[0xff; 6]);
    for i in 0..16 {
        let base = (i + 1) * 6;
        // We know that `buffer` is large enough.
        #[allow(clippy::indexing_slicing)]
        buffer[base..base + 6].copy_from_slice(mac_address.as_bytes());
    }
}

/// Fill a buffer with a magic packet with a SecureON token.
///
/// Fill `buffer` with a magic packet to wake up `mac_address`, using the
/// `secure_on` token.
#[allow(clippy::missing_panics_doc)]
pub fn fill_magic_packet_secure_on(
    buffer: &mut [u8; 108],
    mac_address: MacAddr6,
    secure_on: SecureOn,
) {
    // We know that `buffer` is >= 102 characters so this will never panic.
    fill_magic_packet((&mut buffer[..102]).try_into().unwrap(), mac_address);
    buffer[102..].copy_from_slice(secure_on.as_ref());
}

/// Write a magic packet to a buffer.
///
/// Write a magic packet to `sink`, to wake up `mac_address`.  If `secure_on` is
/// not `None`, include it at the end of the magic packet.
///
/// See [`SecureOn`] for more information about SecureON.
///
/// # Errors
///
/// Return an error if the underlying [`Write::write_all`] fails.
pub fn write_magic_packet<W: Write>(
    sink: &mut W,
    mac_address: MacAddr6,
    secure_on: Option<SecureOn>,
) -> std::io::Result<()> {
    sink.write_all(&[0xff; 6])?;
    for _ in 0..16 {
        sink.write_all(mac_address.as_bytes())?;
    }
    if let Some(secure_on) = secure_on {
        sink.write_all(secure_on.as_ref())?;
    }
    Ok(())
}

/// A socket which supports sending a magic packet.
pub trait SendMagicPacket {
    /// Send a magic packet over this socket.
    ///
    /// Send a magic packet to wake up `mac_address` over this socket.  If
    /// `secure_on` is not `None`, include the SecureON token in the packet.
    /// Use `addr` as destination address for the packet.
    ///
    /// # SecureON
    ///
    /// In addition to the `mac_address`, you can optionally include a shared
    /// "SecureON" token in the magic packet.
    ///
    /// See [`SecureOn`] for more information.
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
        secure_on: Option<SecureOn>,
        addr: A,
    ) -> std::io::Result<()>;
}

impl SendMagicPacket for UdpSocket {
    fn send_magic_packet<A: ToSocketAddrs>(
        &self,
        mac_address: MacAddr6,
        secure_on: Option<SecureOn>,
        addr: A,
    ) -> std::io::Result<()> {
        if let Some(secure_on) = secure_on {
            let mut packet = [0; 108];
            fill_magic_packet_secure_on(&mut packet, mac_address, secure_on);
            let size = self.send_to(&packet, addr)?;
            // `send_to` won't send partial data until i32::MAX, according to
            // `UdpSocket::send-to`, so if we get a partial write nonetheless
            // something's seriously wrong, and we should just crash for satefy.
            assert!(size == packet.len());
        } else {
            let mut packet = [0; 102];
            fill_magic_packet(&mut packet, mac_address);
            let size = self.send_to(&packet, addr)?;
            // Same here
            assert!(size == packet.len());
        }
        Ok(())
    }
}

/// Send one magic packet.
///
/// Bind a new UDP socket to send a magic packet.  If `addr` is an IPv4 address
/// bind to [`Ipv4Addr::UNSPECIFIED`], otherwise bind [`Ipv6Addr::UNSPECIFIED`].
/// Then send a magic packet to wake up `mac_address` over this socket, to the
/// given destination `addr`.
///
/// If `secure_on` is not `None`, include the SecureON token in the magic
/// packet. See [`SecureOn`] for more information about SecureON.
///
/// See [`SendMagicPacket::send_magic_packet`] for details about the arguments.
///
/// # Errors
///
/// Return errors from underlying socket I/O.
pub fn send_magic_packet(
    mac_address: MacAddr6,
    secure_on: Option<SecureOn>,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let bind_address = if addr.is_ipv4() {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::from(Ipv6Addr::UNSPECIFIED)
    };
    let socket = UdpSocket::bind((bind_address, 0))?;
    socket.set_broadcast(true)?;
    socket.send_magic_packet(mac_address, secure_on, addr)
}

#[cfg(test)]
mod tests {
    use crate::{fill_magic_packet, fill_magic_packet_secure_on};

    use super::{MacAddr6, write_magic_packet};

    #[test]
    fn test_fill_magic_packet() {
        let mac_address = "26:CE:55:A5:C2:33".parse::<MacAddr6>().unwrap();
        let mut buffer = [0; 102];
        fill_magic_packet(&mut buffer, mac_address);
        let expected_packet: [u8; 102] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Six all 1 bytes
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
    fn test_fill_magic_packet_secure_on() {
        let secure_on = [0x12, 0x13, 0x14, 0x15, 0x16, 0x42];
        let mac_address = "26:CE:55:A5:C2:33".parse::<MacAddr6>().unwrap();
        let mut buffer = [0; 108];
        fill_magic_packet_secure_on(&mut buffer, mac_address, secure_on.into());
        let expected_packet: [u8; 108] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Six all 1 bytes
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
            0x12, 0x13, 0x14, 0x15, 0x16, 0x42, // SecureON
        ];
        assert_eq!(buffer, expected_packet);
    }

    #[test]
    fn test_write_magic_packet() {
        let mac_address = "26:CE:55:A5:C2:33".parse::<MacAddr6>().unwrap();
        let mut buffer = Vec::new();
        write_magic_packet(&mut buffer, mac_address, None).unwrap();
        let expected_packet: [u8; 102] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Six all 1 bytes
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

    #[test]
    fn test_write_magic_packet_secure_on() {
        let secure_on = [0x12, 0x13, 0x14, 0x15, 0x16, 0x42];
        let mac_address = "26:CE:55:A5:C2:33".parse::<MacAddr6>().unwrap();
        let mut buffer = Vec::new();
        write_magic_packet(&mut buffer, mac_address, Some(secure_on.into())).unwrap();
        let expected_packet: [u8; 108] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Six all 1 bytes
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
            0x12, 0x13, 0x14, 0x15, 0x16, 0x42, // SecureON
        ];
        assert_eq!(buffer.as_slice(), expected_packet.as_slice());
    }
}
