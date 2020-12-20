# extcap-rs

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
[![dependency status][deps-image]][deps-link]
![MIT licensed][license-image]

This crate helps writing [extcap][wireshark-extcap] plugins for [Wireshark][wireshark].

See [Extcap: Developer Guide][wireshark-extcap-dev] also.

_Note: `tokio 0.2` is used because of `tokio-serial`_

## License

Dual licensed under your choice of either of:

 - Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 - MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

[crate-image]: https://img.shields.io/crates/v/extcap.svg
[crate-link]: https://crates.io/crates/extcap
[docs-image]: https://docs.rs/extcap/badge.svg
[docs-link]: https://docs.rs/extcap/
[build-image]: https://github.com/tkeksa/extcap-rs/workflows/ci/badge.svg
[build-link]: https://github.com/tkeksa/extcap-rs/actions
[deps-image]: https://deps.rs/repo/github/tkeksa/extcap-rs/status.svg
[deps-link]: https://deps.rs/repo/github/tkeksa/extcap-rs
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[wireshark]: https://www.wireshark.org/
[wireshark-extcap]: https://www.wireshark.org/docs/man-pages/extcap.html
[wireshark-extcap-dev]: https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
