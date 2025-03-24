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
    // We must use Gtk's APIs to exit the app.
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

use std::io::Write;

/// MAC address types.
pub use macaddr;
pub use macaddr::MacAddr6;

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

#[cfg(test)]
mod tests {
    use super::{MacAddr6, write_magic_packet};

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
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
            0x26, 0xCE, 0x55, 0xA5, 0xC2, 0x33, //
        ];
        assert_eq!(buffer.as_slice(), expected_packet.as_slice());
    }
}
