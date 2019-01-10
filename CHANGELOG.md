# `jail_exporter`

## Upcoming

  - Change templating library from [handlebars] to [askama].
  - Attempts at taking care of some [clippy] warnings.

## v0.9.0

  - Implemented landing page at HTTP web root which simply links to the
    `--web.telemetry-path`. This makes viewing exporter output from a browser
    a slightly more friendly experience.
  - Declare `#![forbid(unsafe_code)]` as we aren't implementing any `unsafe`
    blocks directly.
  - Update to `env_logger` 0.6 and `lazy_static` 1.2.

## v0.8.0

  - Added `CHANGELOG.md`
  - Updated to Rust 1.31 and 2018 edition.
  - Added FreeBSD `rc.d` script.
  - Switched from [warp] to [actix-web] for HTTP related functions.
  - Update to [jail] 0.0.6 and [rctl] 0.0.5.
  - Deal with errors if HTTP server can't bind to address.
  - Simplify metrics HTTP response handler.
  - Provided more metadata in `Cargo.toml`.

<!-- Links -->
[actix-web]: https://crates.io/crates/actix-web
[askama]: https://crates.io/crates/askama
[clippy]: https://github.com/rust-lang/rust-clippy
[handlebars]: https://crates.io/crates/handlebars
[jail]: https://crates.io/crates/jail
[rctl]: https://crates.io/crates/rctl
[warp]: https://crates.io/crates/warp
