# Jail Exporter

Jail Exporter is a [Prometheus] exporter for [FreeBSD] jail metrics as reported
by [`rctl(8)`].

The exporter is written in [Rust] and uses the C FFI to obtain the relavent
data from [`jail_get(2)`] (via [`libjail-rs`]) and [`rctl_get_racct(2)`] (via
`libjail-rs` and [`librctl-rs`]).

## Configuration

All configuration is via the command line, the arguments you may use are shown
in the following table:

Argument             | Default          | Purpose
---------------------|------------------|--------
`web.listen-address` | `127.0.0.1:9452` | Address on which to expose metrics and web interface.
`web.telemetry-path` | `/metrics`       | Path under which to expose metrics.

## Running

The exporter needs to run as `root` in order to have enough permission to
execute the [`rctl_get_racct(2)`] calls.

No port or `rc(8)` script is available yet, but work on a port will happen
soon.

## Exposed Metrics

This exporter was developed under FreeBSD 11.1 and currently exports all
resources listed under the `RESOURCES` section of [`rctl(8)`] with the
exception of `readbps`, `writebps`, `readiops`, and `writeiops` as these are
listed as being difficult to measure properly. They may appear in the future.

The `id` and `num` time series are calculated based on other information and do
not come from [`rctl(8)`] directly. 

All exported metrics are prefixed with `jail` and have a `name` label
representing the name of the jail. As such, jail names are expected to be
unique.

Descriptions of metrics are taken from the [`rctl(8)`] man page where
applicable.

Metric                    | `rctl(8)` name    | Description
--------------------------|-------------------|------------
`coredumpsize_bytes`      | `coredumpsize`    | core dump size, in bytes
`cputime_seconds_total`   | `cputime`         | CPU time, in seconds
`datasize_bytes`          | `datasize`        | data size, in bytes
`id`                      | N/A               | ID of the named jail
`maxproc`                 | `maxproc`         | number of processes
`memorylocked_bytes`      | `memorylocked`    | locked memory, in bytes
`memoryuse_bytes`         | `memoryuse`       | resident set size, in bytes
`msgqqueued`              | `msgqqueued`      | number of queued SysV messages
`msgqsize_bytes`          | `msgqsize`        | SysV message queue size, in bytes
`nmsgq`                   | `nmsgq`           | number of SysV message queues
`nsem`                    | `nsem`            | number of SysV semaphores
`nsemop`                  | `nsemop`          | number of SysV semaphores modified in a single semop(2) call
`nshm`                    | `nshm`            | number of SysV shared memory segments
`nthr`                    | `nthr`            | number of threads
`num`                     | N/A               | Current number of running jails
`openfiles`               | `openfiles`       | file descriptor table size
`pcpu_used`               | `pcpu`            | %CPU, in percents of a single CPU core
`pseudoterminals`         | `pseudoterminals` | number of PTYs
`shmsize_bytes`           | `shmsize`         | SysV shared memory size, in bytes
`stacksize_bytes`         | `stacksize`       | stack size, in bytes
`swapuse_bytes`           | `swapuse`         | swap space that may be reserved or used, in bytes
`vmemoryuse_bytes`        | `vmemoryuse`      | address space limit, in bytes
`wallclock_seconds_total` | `wallclock`       | wallclock time, in seconds

[FreeBSD]: https://www.freebsd.org/
[Prometheus]: https://prometheus.io/
[Rust]: https://www.rust-lang.org/
[`jail_get(2)`]: https://www.freebsd.org/cgi/man.cgi?query=jail_get&sektion=2
[`libjail-rs`]: https://github.com/fubarnetes/libjail-rs
[`librctl-rs`]: https://github.com/fubarnetes/rctl
[`rctl(8)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl&sektion=8
[`rctl_get_racct(2)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl_get_racct&sektion=2
