# wol.rs

[![Current release](https://img.shields.io/crates/v/wol.svg)][crates]
[![Documentation](https://docs.rs/wol/badge.svg)][docs]

Wake On LAN magic packet command line tool and crate.

[crates]: https://crates.io/crates/wol
[docs]: https://docs.rs/wol

## Command line

```console
$ wol --verbose --port 42 12:13:14:15:16:17
Waking up 12:13:14:15:16:17 with 255.255.255.255:42...
```

See `wol --help` for more information.

## Installation

- [Arch binary package](https://build.opensuse.org/package/show/home:swsnr/wol-rs)
- `cargo install --all-features wol`
- 3rd party packages: [Repology](https://repology.org/project/wol-rs/versions)

For packaging, all releases have reproducible git archive and cargo vendor
bundles attached, built and attested by a Github workflow.  You can use
`gh attestation verify` to check these attestations. I recommend to first build
with `--all-features`, then dump the manpage and desired completions with
`--print-manpage` and `--print-completions`, and eventually build with
`--features cli` to remove these options from the final binary. See arch package
above for an example.

## Crate

You can also use `wol` as a Rust crate, with `cargo add wol`:

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
