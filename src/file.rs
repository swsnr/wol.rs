// Copyright Sebastian Wiesner <sebastian@swsnr.de>
//
// Licensed under the EUPL
//
// See https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12

//! Parse "wakeup files".
//!
//! A "wakeup file" is a file containing lines denoting systems to wake up.
//! Each line is a whitespace-separated sequence of hardware address, and
//! optionally packet destination, port, and SecureON token. See
//! [`WakeUpTarget`] for documentation for details.
//!
//! Blank lines and lines starting with `#` are ignored.
//!
//! Use [`from_lines`] or [`from_reader`] to read wakeup files.

use std::fmt::Display;
use std::io::{BufRead, Error, ErrorKind};
use std::net::IpAddr;
use std::num::ParseIntError;
use std::str::FromStr;

use macaddr::MacAddr6;

use crate::{MacAddress, SecureOn};

/// A destination to send a magic packet to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicPacketDestination {
    /// A DNS name to be resolved into an IP address.
    Dns(String),
    /// An IP address.
    Ip(IpAddr),
}

impl Display for MagicPacketDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MagicPacketDestination::Dns(name) => write!(f, "{name}"),
            MagicPacketDestination::Ip(ip_addr) => write!(f, "{ip_addr}"),
        }
    }
}

impl From<String> for MagicPacketDestination {
    fn from(value: String) -> Self {
        IpAddr::from_str(&value)
            .ok()
            .map_or_else(|| Self::Dns(value), Self::Ip)
    }
}

/// A single target to wake up.
///
/// # String format
///
/// Wake up targets can be parsed from strings in the following format:
///
/// ```text
/// <hardware-address> [<IP/DNS name>] [<port>] [<secure-on>]
/// ```
///
/// Except for the hardware address all other fields are optional.
///
/// The MAC address is given as six hexadecimal bytes separated by dashes or
/// colons, e.g `XX-XX-XX-XX-XX-XX` or `XX:XX:XX:XX:XX:XX`.
///
/// The SecureON is given in the same format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeUpTarget {
    hardware_address: MacAddress,
    packet_destination: Option<MagicPacketDestination>,
    port: Option<u16>,
    secure_on: Option<SecureOn>,
}

impl WakeUpTarget {
    /// Create a new wake up target for the given `hardware_address`.
    #[must_use]
    pub fn new(hardware_address: MacAddress) -> Self {
        Self {
            hardware_address,
            packet_destination: None,
            port: None,
            secure_on: None,
        }
    }

    /// Get the hardware address.
    #[must_use]
    pub fn hardware_address(&self) -> MacAddress {
        self.hardware_address
    }

    /// Get the host to send the magic packet to if any.
    ///
    /// This is usually not the same host as the one to wake up; rather it
    /// should be a broadcast address.
    #[must_use]
    pub fn packet_destination(&self) -> Option<&MagicPacketDestination> {
        self.packet_destination.as_ref()
    }

    /// Get the port to send the magic packet to.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Get the SecureON token to include in the packet if any.
    #[must_use]
    pub fn secure_on(&self) -> Option<SecureOn> {
        self.secure_on
    }

    /// Change the hardware address.
    #[must_use]
    pub fn with_hardware_address(mut self, hardware_address: MacAddress) -> Self {
        self.hardware_address = hardware_address;
        self
    }

    /// Change the packet destination.
    #[must_use]
    pub fn with_packet_destination(
        mut self,
        packet_destination: Option<MagicPacketDestination>,
    ) -> Self {
        self.packet_destination = packet_destination;
        self
    }

    /// Change the packet destination.
    #[must_use]
    pub fn with_dns_packet_destination(mut self, dns: String) -> Self {
        self.packet_destination = Some(MagicPacketDestination::Dns(dns));
        self
    }

    /// Change the packet destination.
    #[must_use]
    pub fn with_ip_packet_destination(mut self, ip: IpAddr) -> Self {
        self.packet_destination = Some(MagicPacketDestination::Ip(ip));
        self
    }

    /// Change the destination port for the magic packet.
    #[must_use]
    pub fn with_port(mut self, port: Option<u16>) -> Self {
        self.port = port;
        self
    }

    /// Change the SecureON token for this target.
    #[must_use]
    pub fn with_secure_on(mut self, secure_on: Option<SecureOn>) -> Self {
        self.secure_on = secure_on;
        self
    }
}

/// An invalid wake up target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeUpTargetParseError {
    /// The string was empty or consistent only of whitespace,
    Empty,
    /// The hardware address in field 1 was invalid.
    InvalidHardwareAddress(macaddr::ParseError),
    /// The port number in the given field was invalid.
    InvalidPort(u8, ParseIntError),
    /// The SecureON token in the given was invalid.
    InvalidSecureOn(u8, macaddr::ParseError),
    /// The line had more than the expected number of fields.
    TooManyFields(usize),
}

impl Display for WakeUpTargetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Line empty"),
            Self::InvalidHardwareAddress(parse_error) => {
                // The hardware address is always in the first field
                write!(f, "Field 1: Invalid hardware address: {parse_error}")
            }
            Self::InvalidPort(field, error) => {
                write!(f, "Field {field}: Invalid port number: {error}")
            }
            Self::InvalidSecureOn(field, error) => {
                write!(f, "Field {field}: Invalid SecureON token: {error}")
            }

            Self::TooManyFields(fields) => write!(f, "Expected 4 fields, got {fields}"),
        }
    }
}

impl std::error::Error for WakeUpTargetParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHardwareAddress(parse_error) => Some(parse_error),
            Self::InvalidPort(_, error) => Some(error),
            Self::InvalidSecureOn(_, error) => Some(error),
            Self::TooManyFields(_) | Self::Empty => None,
        }
    }
}

impl FromStr for WakeUpTarget {
    type Err = WakeUpTargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split_ascii_whitespace().collect::<Vec<_>>();
        match parts[..] {
            [] => Err(Self::Err::Empty),
            [field_1] => MacAddr6::from_str(field_1)
                .map_err(Self::Err::InvalidHardwareAddress)
                .map(|macaddr| Self::new(MacAddress::from(macaddr.into_array()))),
            [field_1, field_2] => {
                let mut line = MacAddr6::from_str(field_1)
                    .map_err(Self::Err::InvalidHardwareAddress)
                    .map(|macaddr| Self::new(MacAddress::from(macaddr.into_array())))?;
                if let Ok(secure_on) = MacAddr6::from_str(field_2) {
                    line.secure_on = Some(SecureOn(secure_on.into_array()));
                } else if let Ok(port) = u16::from_str(field_2) {
                    line.port = Some(port);
                } else {
                    line.packet_destination =
                        Some(MagicPacketDestination::from(field_2.to_owned()));
                }
                Ok(line)
            }
            [field_1, field_2, field_3] => {
                let mut line = MacAddr6::from_str(field_1)
                    .map_err(Self::Err::InvalidHardwareAddress)
                    .map(|macaddr| Self::new(MacAddress::from(macaddr.into_array())))?;
                match MacAddr6::from_str(field_3) {
                    Ok(secure_on) => {
                        line.secure_on = Some(SecureOn(secure_on.into_array()));
                        if let Ok(port) = u16::from_str(field_2) {
                            line.port = Some(port);
                        } else {
                            line.packet_destination =
                                Some(MagicPacketDestination::from(field_2.to_owned()));
                        }
                        Ok(line)
                    }
                    Err(error) if field_3.contains(['.', ':', '-']) => {
                        // If the 3rd field contains MAC address separators, it definitely can't be a valid numeric port,
                        // and is likely just an invalid SecureON password.
                        Err(Self::Err::InvalidSecureOn(3, error))
                    }
                    Err(_) => {
                        // If field 3 is not a SecureON password, then field 3 must be a port
                        line.packet_destination =
                            Some(MagicPacketDestination::from(field_2.to_owned()));
                        line.port = Some(
                            u16::from_str(field_3).map_err(|err| Self::Err::InvalidPort(3, err))?,
                        );
                        Ok(line)
                    }
                }
            }
            [field_1, field_2, field_3, field_4] => Ok(MacAddr6::from_str(field_1)
                .map_err(Self::Err::InvalidHardwareAddress)
                .map(|macaddr| Self::new(MacAddress::from(macaddr.into_array())))?
                .with_packet_destination(Some(MagicPacketDestination::from(field_2.to_owned())))
                .with_port(Some(
                    u16::from_str(field_3).map_err(|err| Self::Err::InvalidPort(3, err))?,
                ))
                .with_secure_on(Some(
                    MacAddr6::from_str(field_4)
                        .map(|secure_on| SecureOn(secure_on.into_array()))
                        .map_err(|error| Self::Err::InvalidSecureOn(4, error))?,
                ))),
            _ => Err(Self::Err::TooManyFields(parts.len())),
        }
    }
}

/// An invalid [`WakeUpTarget`] in an iterator over lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLineError(usize, WakeUpTargetParseError);

impl ParseLineError {
    /// Create a new error.
    ///
    /// `line_no` denotes the 1-based number of the faulty line, and `error` is
    /// the error which occurred while parsing that line.
    #[must_use]
    pub fn new(line_no: usize, error: WakeUpTargetParseError) -> Self {
        Self(line_no, error)
    }

    /// The line number at which the error occurred.
    #[must_use]
    pub fn line_no(&self) -> usize {
        self.0
    }

    /// The error at this line.
    #[must_use]
    pub fn error(&self) -> &WakeUpTargetParseError {
        &self.1
    }
}

impl Display for ParseLineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Line {}: {}", self.0, self.1)
    }
}

impl std::error::Error for ParseLineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.1)
    }
}

fn parse_line(i: usize, line: &str) -> Option<Result<WakeUpTarget, ParseLineError>> {
    if line.trim().is_empty() || line.trim().starts_with('#') {
        None
    } else {
        Some(WakeUpTarget::from_str(line).map_err(|error| ParseLineError(i + 1, error)))
    }
}

/// Parse targets from an iterator over lines.
///
/// Ignore empty lines, or lines starting with `#`, and try to parse all other
/// lines as [`WakeUpTarget`]s.
///
/// Return an iterator over results from parsing lines, after ignoring empty
/// or comment lines.  Each item is either a parsed target, or an error which
/// occurred while parsing a line.
pub fn from_lines<I, S>(lines: I) -> impl Iterator<Item = Result<WakeUpTarget, ParseLineError>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    lines
        .into_iter()
        .enumerate()
        .filter_map(|(i, line)| parse_line(i, line.as_ref()))
}

/// Parse targets from lines read from a reader.
///
/// See [`from_lines`] for more information.
///
/// Return an iterator over results from parsing lines, after ignoring empty
/// or comment lines.  Each item is either a parsed target, or an error which
/// occurring while reading or parsing a line.
///
/// If a line fails to parse the [`ParseLineError`] is wrapped in an
/// [`std::io::Error`], with [`ErrorKind::InvalidData`].
pub fn from_reader<R: BufRead>(reader: R) -> impl Iterator<Item = Result<WakeUpTarget, Error>> {
    reader.lines().enumerate().filter_map(|(i, line)| {
        line.and_then(|line| {
            parse_line(i, &line)
                .transpose()
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))
        })
        .transpose()
    })
}

#[cfg(test)]
mod tests {
    use std::{io::BufReader, net::IpAddr, str::FromStr};

    use super::*;

    #[test]
    fn test_target_from_string_empty() {
        assert!(WakeUpTarget::from_str("").is_err());
        assert!(WakeUpTarget::from_str("        ").is_err());
        assert!(WakeUpTarget::from_str("\t").is_err());
    }

    #[test]
    fn test_target_from_string_hardware_address_only() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
        );
        assert_eq!(
            WakeUpTarget::from_str("12-13-14-15-16-17").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
        );
        assert_eq!(
            WakeUpTarget::from_str("  12:13:14:15:16:17  ").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
        );
        assert_eq!(
            WakeUpTarget::from_str("  jj:13:14:15:16:17  ").unwrap_err(),
            WakeUpTargetParseError::InvalidHardwareAddress(macaddr::ParseError::InvalidCharacter(
                'j', 1
            ))
        );
        assert_eq!(
            WakeUpTarget::from_str("  12:13:14:15:16:17:18  ").unwrap_err(),
            WakeUpTargetParseError::InvalidHardwareAddress(macaddr::ParseError::InvalidLength(20))
        );
    }

    #[test]
    fn test_target_from_string_hardware_address_and_destination() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 foo.example.com").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_dns_packet_destination("foo.example.com".into())
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.4").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_ip_packet_destination(IpAddr::from_str("192.0.2.4").unwrap())
        );
    }

    #[test]
    fn test_target_from_string_hardware_address_and_port() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 9").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_port(Some(9))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 09").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_port(Some(9))
        );
    }

    #[test]
    fn test_target_from_string_hardware_address_and_secure_on() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 aa-bb-cc-dd-ee-ff").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_secure_on(Some(SecureOn::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 aa-bb-cc-dd-ee-f").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_dns_packet_destination("aa-bb-cc-dd-ee-f".into())
        );
    }

    #[test]
    fn test_target_from_string_hardware_address_and_host_and_port() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 foo.example.com 23").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_dns_packet_destination("foo.example.com".into())
                .with_port(Some(23))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.4 23").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_ip_packet_destination(IpAddr::from_str("192.0.2.4").unwrap())
                .with_port(Some(23))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.4 foo").unwrap_err(),
            WakeUpTargetParseError::InvalidPort(3, u16::from_str("foo").unwrap_err())
        );
    }

    #[test]
    fn test_target_from_string_hardware_address_and_host_and_secure_on() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 foo.example.com aa-bb-cc-dd-ee-ff").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_dns_packet_destination("foo.example.com".into())
                .with_secure_on(Some(SecureOn::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.4 aa-bb-cc-dd-ee-ff").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_ip_packet_destination(IpAddr::from_str("192.0.2.4").unwrap())
                .with_secure_on(Some(SecureOn::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.4 aa-bb-cc-dd-ee-f").unwrap_err(),
            WakeUpTargetParseError::InvalidSecureOn(3, macaddr::ParseError::InvalidLength(16))
        );
    }

    #[test]
    fn test_target_from_string_hardware_address_and_port_and_secure_on() {
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 42 aa-bb-cc-dd-ee-ff").unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_port(Some(42))
                .with_secure_on(Some(SecureOn::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])))
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 42 aa-bb-cc-dd-ee-f").unwrap_err(),
            WakeUpTargetParseError::InvalidSecureOn(3, macaddr::ParseError::InvalidLength(16))
        );
    }

    #[test]
    fn test_target_from_string_full() {
        let line =
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.42 42 aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(
            line.hardware_address(),
            MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
        );
        assert_eq!(
            line.packet_destination(),
            Some(&MagicPacketDestination::Ip(
                IpAddr::from_str("192.0.2.42").unwrap()
            ))
        );
        assert_eq!(line.port(), Some(42));
        assert_eq!(
            line.secure_on(),
            Some(SecureOn([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
    }

    #[test]
    fn test_line_from_string_too_many_fields() {
        assert_eq!(
            WakeUpTarget::from_str("a b c d e f g   ").unwrap_err(),
            WakeUpTargetParseError::TooManyFields(7)
        );
        assert_eq!(
            WakeUpTarget::from_str("12:13:14:15:16:17 192.0.2.42 42 aa-bb-cc-dd-ee-ff extra")
                .unwrap_err(),
            WakeUpTargetParseError::TooManyFields(5)
        );
    }

    #[test]
    fn test_from_lines() {
        let file = "# A test file

  # A bad line
12:13:14:15:16:17 192.0.2.42 42 aa-bb-cc-dd-ee-ff extra

# A good line
12:13:14:15:16:17 192.0.2.42 42 aa-bb-cc-dd-ee-ff

# A short line
12:13:14:15:16:17 23";
        let targets = from_lines(file.lines()).collect::<Vec<_>>();
        assert_eq!(
            targets,
            vec![
                Err(ParseLineError::new(
                    4,
                    WakeUpTargetParseError::TooManyFields(5)
                )),
                Ok(
                    WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                        .with_ip_packet_destination(IpAddr::from_str("192.0.2.42").unwrap())
                        .with_port(Some(42))
                        .with_secure_on(Some(SecureOn::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])))
                ),
                Ok(
                    WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                        .with_port(Some(23))
                )
            ]
        );
    }

    #[test]
    fn test_from_reader() {
        let file = "# A test file

  # A bad line
12:13:14:15:16:17 192.0.2.42 42 aa-bb-cc-dd-ee-ff extra

# A good line
12:13:14:15:16:17 192.0.2.42 42 aa-bb-cc-dd-ee-ff

# A short line
12:13:14:15:16:17 23";
        let reader = BufReader::new(file.as_bytes());
        let mut targets = from_reader(reader);
        let error = targets.next().unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(
            *error
                .into_inner()
                .unwrap()
                .downcast::<ParseLineError>()
                .unwrap(),
            (ParseLineError::new(4, WakeUpTargetParseError::TooManyFields(5)))
        );
        assert_eq!(
            targets.next().unwrap().unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_ip_packet_destination(IpAddr::from_str("192.0.2.42").unwrap())
                .with_port(Some(42))
                .with_secure_on(Some(SecureOn::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])))
        );
        assert_eq!(
            targets.next().unwrap().unwrap(),
            WakeUpTarget::new(MacAddress::from([0x12, 0x13, 0x14, 0x15, 0x16, 0x17]))
                .with_port(Some(23))
        );
        assert!(targets.next().is_none());
    }
}
