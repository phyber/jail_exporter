# `jail_exporter`

## v0.9.5

  - Attempts at taking care of some [clippy] warnings.
  - Change templating library from [handlebars] to [askama].
  - Move exporter into the `AppState` struct, removing the requirement for
    [lazy_static] in the release binaries.
  - Created a `jail_exporter(8)` man page.
  - Move some helper code out of `main` into their own functions.
  - Moved HTTP related code out to `httpd` module, simplifying `main` function.
  - `jail_exporter::Metrics` is now `#[derive(Clone)]`
  - Fixed a bug where Metrics would attempt initialization once per Actix Web
    thread.
  - Added Actix Web Logger middleware to HTTP server.
  - `jail_exporter` now attempts to ensure that it's running as `root` before
    starting.
  - Updated to version 0.5 of the [prometheus] crate.
  - Now using a builder pattern for the HTTP server instead of multiple
    arguments to a run function.
  - Added a validator for the `web.telemetry-path` setting.
  - Moved to using [failure] crate and removed explicit `exit` calls on error
    conditions by using `Result` return on `main` function.

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
[failure]: https://crates.io/crates/failure
[handlebars]: https://crates.io/crates/handlebars
[jail]: https://crates.io/crates/jail
[lazy_static]: https://crates.io/crates/lazy_static
[prometheus]: https://crates.io/crates/prometheus
[rctl]: https://crates.io/crates/rctl
[warp]: https://crates.io/crates/warp
