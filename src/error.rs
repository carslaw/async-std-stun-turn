//! Custom errors that are used by the STUN and TURN implementations and 
//! examples.
//! 
//! These mainly handle STUN and TURN specific errors. IO and
//! bytecodec errors are included to deal with errors from timeout  
//! and stun_codec errors respectively.
//!


use stun_codec::rfc5389::errors::*;
use stun_codec::rfc5766::errors::*;
use std::error::Error;
use std::fmt;
use std::io;


#[derive(Debug)]
pub enum StunTurnErrors {
    Io(io::Error),
    String(std::string::String),
    ByteCodec(bytecodec::Error),
    BadRequest,
    ServerError,
    StaleNonce,
    TryAlternate,
    Unauthorized,
    UnknownAttribute,
    AllocationMismatch,
    AllocationQuotaReached,
    Forbidden,
    InsufficientCapacity,
    UnsupportedTransportProtocol,
    WrongCredentials,
    NotStunTurnError,
    PermissionTimedOut,
}

impl fmt::Display for StunTurnErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StunTurnErrors::Io(ref err) => err.fmt(f),
            StunTurnErrors::String(ref err) => err.fmt(f),
            StunTurnErrors::ByteCodec(ref err) => err.fmt(f),
            StunTurnErrors::BadRequest                          => write!(f, "{:?}", BadRequest),
            StunTurnErrors::ServerError                         => write!(f, "{:?}", ServerError),
            StunTurnErrors::StaleNonce                          => write!(f, "{:?}", StaleNonce),
            StunTurnErrors::TryAlternate                        => write!(f, "{:?}", TryAlternate),
            StunTurnErrors::Unauthorized                        => write!(f, "{:?}", Unauthorized),
            StunTurnErrors::UnknownAttribute                    => write!(f, "{:?}", UnknownAttribute),
            StunTurnErrors::AllocationMismatch                  => write!(f, "{:?}", AllocationMismatch),
            StunTurnErrors::AllocationQuotaReached              => write!(f, "{:?}", AllocationQuotaReached),
            StunTurnErrors::Forbidden                           => write!(f, "{:?}", Forbidden),
            StunTurnErrors::InsufficientCapacity                => write!(f, "{:?}", InsufficientCapacity),
            StunTurnErrors::UnsupportedTransportProtocol        => write!(f, "{:?}", UnsupportedTransportProtocol),
            StunTurnErrors::WrongCredentials                    => write!(f, "{:?}", WrongCredentials),
            StunTurnErrors::NotStunTurnError                    => write!(f, "Not a STUN or TURN error code"),
            StunTurnErrors::PermissionTimedOut                  => write!(f, "Permission timed out"),
        }
    }
 }

impl std::convert::From<io::Error> for StunTurnErrors {
    fn from(error: io::Error) -> Self {
        StunTurnErrors::Io(error)
    }
 }

impl std::convert::From<std::string::String> for StunTurnErrors {
    fn from(error: std::string::String) -> Self {
        StunTurnErrors::String(error)
    }
}

impl std::convert::From<bytecodec::Error> for StunTurnErrors {
    fn from(error: bytecodec::Error) -> Self {
        StunTurnErrors::ByteCodec(error)
    }
}

impl Error for StunTurnErrors { }

