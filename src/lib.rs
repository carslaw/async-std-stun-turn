//! This crate contains implementations of [STUN] and [TURN] using the [async-std] 
//! runtime. It also uses [stun_codec] to encode and decode the STUN messages.
//! 
//! [STUN]: https://tools.ietf.org/html/rfc8489
//! [TURN]: https://tools.ietf.org/html/rfc8656
//! [async-std]: https://async.rs/
//! [stun_codec]: https://github.com/sile/stun\_ccodec
//! 
//! Examples of how to use the STUN and TURN clients can be found in the test.rs file. 
//! Examples of servers can be found in main.rs

pub mod stun;
pub mod turn;
pub mod error;
pub mod tests;