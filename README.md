# wol.rs

[![Current release](https://img.shields.io/crates/v/wol.svg)][crates]
[![Documentation](https://docs.rs/wol/badge.svg)][docs]

Wake On LAN magic packet command line tool and crate.

## Command line

```console
$ wol --verbose --port 42 12:13:14:15:16:17
Waking up 12:13:14:15:16:17 with 255.255.255.255:42...
```

See `wol --help` for more information.

Install with `cargo install --features cli wol`.

## Crate

You can also use `wol` as a Rust crate:

```rust
use std::str::FromStr;
use std::net::Ipv4Addr;

let mac_address = wol::MacAddr6::from_str("12-13-14-15-16-17").unwrap();
wol::send_magic_packet(mac_address, None, (Ipv4Addr::BROADCAST, 9).into()).unwrap();
```

See <https://docs.rs/wol> for detailed documentation.

## License

Copyright Sebastian Wiesner <sebastian@swsnr.de>

This program is subject to the terms of the Mozilla Public
License, v. 2.0, see [LICENSE](LICENSE), unless otherwise noted;
some files are subject to the terms of the Apache 2.0 license,
see <http://www.apache.org/licenses/LICENSE-2.0>
