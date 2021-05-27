# User manual

By default, the clients and servers try to run locally. To properly test them
the servers should be run remotely. In the `tests.rs` file, change the `REMOTE_ADDR`
variable to contain the IP address of the remote server and it's port, which
should be 3478. This should take the form of IP:port as shown in the file.
For server reflexive address tests to succeed, when contacting a remote server,
the `ADDR` variable must be changed to the server reflexive address of the
machine that the tests are being run on. The easiest way to find this is
through using a search engine.

Basic documentation can be created using the `cargo doc --no-deps --open command`.
This doesn't generate documentation for the `main.rs` file despite documentation comments
being present in it.

The print statements that are in the client tests are hidden by default. These can be shown
by using the `--nocapture` flag i.e cargo test `turn -- --nocapture --test-threads 1`

## Known Issues

`main.rs` may not run on default rust. This may be fixed by changing to the nightly
version using the `rustup default nightly` command.
