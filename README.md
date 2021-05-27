# Readme

Rust async-std implementations of the [STUN](https://tools.ietf.org/html/rfc8489)
and [TURN](https://tools.ietf.org/html/rfc8656) protocols. Uses the [stun_codec](https://github.com/sile/stun_codec)
library to encode the STUN messages.

The STUN client and server files are in `async_std_stun_turn/src/stun`.
The TURN client and server files are in the `async_std_stun_turn/src/turn` folder.
The client and server examples are present in the `test.rs` and `main.rs` files respectively.

## Build instructions

### Requirements

* rustc 1.51.0
* Cargo 1.51.0
* Required crates listed in `async_std_stun_turn/src/cargo.toml`
* Tested on Manjaro Linux and Amazon Linux
* At least 750mb of storage is required for all of the dependencies that cargo will download.

### Build steps

* `cd async_std_stun_turn/src`
* `cargo build`

### Test steps

* `cargo run` then enter "stun", "turn" or "peer" to run the respective server.
* `cargo test stun` to run STUN tests
* `cargo test turn -- --test-threads 1` to run TURN tests.

All but one of the tests will fail without their respective server running.
Some of the TURN tests may not work if they are all run at the same time. Choosing an
individual one, with a command like `cargo test turn_allocate -- --test-threads 1`, may work better.

For tests that attempt an allocation, data can be entered in the command line running the client to be relayed.
Entering no data will cause the client to close the allocation.

Running `bash server.sh`, in the directory above this file, will attempt to run the
AWS server. However, the ssh won't be authenticated so it will fail.
