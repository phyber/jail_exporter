# `jail_exporter`

## v0.8.0

  - Added `CHANGELOG.md`
  - Updated to Rust 1.31 and 2018 edition.
  - Added FreeBSD `rc.d` script.
  - Switched from [warp] to [actix-web] for HTTP related functions.
  - Update to [libjail] 0.0.6 and [rctl] 0.0.5.
  - Deal with errors if HTTP server can't bind to address.
  - Simplify metrics HTTP response handler.

<!-- Links -->
[actix-web]: https://actix.rs/
[libjail]: https://github.com/fubarnetes/libjail-rs
[rctl]: https://github.com/fubarnetes/rctl
[warp]: https://github.com/seanmonstar/warp
