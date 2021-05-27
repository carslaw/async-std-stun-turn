use crate::stun::async_stun_client::StunClient;
use stun_codec::rfc5389::attributes::*;
use stun_codec::rfc5766::attributes::*;
use stun_codec::rfc5766::{methods::*, Attribute as T};


use stun_codec::rfc5389::attributes::ErrorCode;
use stun_codec::rfc5389::{methods::BINDING, Attribute as S};
use stun_codec::{Message, MessageClass, TransactionId};
use stun_codec::{MessageDecoder, MessageEncoder};

use async_std::{
    prelude::*,
    net::{SocketAddr, UdpSocket, ToSocketAddrs},
};
use stun_codec::Attribute as A;
use stun_codec::convert::TryAsRef;

use async_std::io;

use bytecodec::{DecodeExt, EncodeExt};


use std::time::Duration;
use std::ops::Sub;

use crate::error::StunTurnErrors;
use std::time::Instant;

///A representation of a TURN client that can create an allocation, refresh it and create permissions. 
/// It can send data to a peer and should receive from a peer as well.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TurnClient {
    pub relayed_addrs : Option<Vec<SocketAddr>>,
    pub ftuple : FiveTuple,
    pub auth : Username,
    pub expiry_time : Option<Duration>,
    pub permissions : Option<Vec<(SocketAddr, Instant)>>,
    // channel_binds : Vec<BINDING>, // Vector to store channels in the future
    pub data : Vec<u8>,
}

/// Stores the local and remote addresses for a connection. Also holds the transport protocol that will be used.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FiveTuple {
    pub local : Option<SocketAddr>,
    pub remote : Option<SocketAddr>,
    pub protocol : u8,
}


impl TurnClient {
    
    /// Decodes a message to extract it's attributes. Can return a combination of the allocated address, 
    /// the client's server reflexive address, a channel number(unused), data from a peer, along with it's address, 
    /// or a bool representing a permission being created successfully.
    /// The messages are decoded twice to get both the STUN and TURN attributes
    pub async fn decode(&self, buf: &[u8]) -> Result<Option<(Option<SocketAddr>, Option<SocketAddr>, Option<Duration>, Option<Vec<ChannelNumber>>, Option<Option<(Vec<u8>, SocketAddr)>>, Option<bool>)>, StunTurnErrors> { //permissions as well
        
        // TURN decoding
        let mut decoder = MessageDecoder::<T>::new();
        let decoded = decoder
            .decode_from_bytes(buf)?
            .map_err(|_| format!("Broken TURN reply"))?;

        // STUN decoding
        let mut stun_decoder = MessageDecoder::<S>::new();
        let stun_decoded = stun_decoder
            .decode_from_bytes(buf)?
            .map_err(|_| format!("Broken TURN reply"))?;
        
        // temporary values to be overwritten
        let mut remote : SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut actual_local : SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut lifetime = Duration::from_secs(3600); // default lifetime

        // Error handling
        if stun_decoded.class() == MessageClass::ErrorResponse {
            for attr in stun_decoded.attributes() {
                match attr.get_type().as_u16() {
                    ErrorCode::CODEPOINT => {
                        let e = (*TryAsRef::<ErrorCode>::try_as_ref(attr).unwrap()).clone();
                        match e.code() {
                            300 => return Err(StunTurnErrors::TryAlternate),
                            400 => return Err(StunTurnErrors::BadRequest),
                            401 => return Err(StunTurnErrors::Unauthorized),
                            403 => return Err(StunTurnErrors::Forbidden),
                            420 => return Err(StunTurnErrors::UnknownAttribute),
                            437 => return Err(StunTurnErrors::AllocationMismatch),
                            438 => return Err(StunTurnErrors::StaleNonce),
                            441 => return Err(StunTurnErrors::WrongCredentials),
                            442 => return Err(StunTurnErrors::UnsupportedTransportProtocol),
                            486 => return Err(StunTurnErrors::AllocationQuotaReached),
                            500 => return Err(StunTurnErrors::ServerError),
                            508 => return Err(StunTurnErrors::InsufficientCapacity),
                            _ => return Err(StunTurnErrors::NotStunTurnError)
                        }
                    },
                    _ => continue
                }
            }
        }
        
        // Checks successfuly creation of a permission
        if decoded.class() == MessageClass::SuccessResponse && decoded.method() == CREATE_PERMISSION {
            return Ok(Some((None, None, None, None, None, Some(true))))
        }

        // Check TURN attributes
        for attr in decoded.attributes() {
            match attr.get_type().as_u16() {
                XorRelayAddress::CODEPOINT => {
                    remote = (*TryAsRef::<XorRelayAddress>::try_as_ref(attr).unwrap()).address();
                    // Check it is in address family
                    if !remote.is_ipv4() {
                        format!("Returned wrong address family");
                    }
                },
                XorPeerAddress::CODEPOINT => {
                    actual_local = (*TryAsRef::<XorPeerAddress>::try_as_ref(attr).unwrap()).address();
                    if !actual_local.is_ipv4() {
                        format!("Returned wrong address family");
                    }
                },
                Lifetime::CODEPOINT => {
                    lifetime = (*TryAsRef::<Lifetime>::try_as_ref(attr).unwrap()).lifetime();
                },
                _ => continue
            }
        }

        if decoded.method() == REFRESH {
            println!("Refresh message received");
            return Ok(Some((None, None, Some(lifetime), None, None, None)))
        }

        // Returns data and peer address
        if decoded.method() == DATA {
            println!("DATA method received");
            let recv = self.receive_data(decoded).await?;
            return Ok(Some((None, None, None, None, Some(recv), None)))
        }
        println!("lifetime is {:?}", lifetime);
        return Ok(Some((Some(remote), Some(actual_local), Some(lifetime), None, None, None)));
    }

    /// Sends a refresh request to the client's allocation on the server.
    pub async fn refresh(&self, time: Duration, alloc: SocketAddr, local: &UdpSocket) -> Result<(), StunTurnErrors> {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

        let mut message = Message::new(MessageClass::Request, REFRESH, TransactionId::new(random_bytes));

        message.add_attribute(Lifetime::new(time).unwrap());

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message.clone())?;
        println!("Refreshing");
        local.send_to(&bytes, alloc).await?;
        
        Ok(())
    }
    
    /// Sends data to an address. Intended for sending to a peer.
    pub async fn send_data(&self, peer_addr: SocketAddr, to_send: Vec<u8>, alloc: SocketAddr, local: &UdpSocket) -> Result<(), StunTurnErrors> {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

        let mut message = Message::new(MessageClass::Indication, SEND, TransactionId::new(random_bytes));
        
        message.add_attribute(T::XorPeerAddress(XorPeerAddress::new(peer_addr)));
        message.add_attribute(T::Data(Data::new(to_send).unwrap()));

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message.clone())?;
        println!("Sending data");
        local.send_to(&bytes, alloc).await?;

        Ok(())
    }

    /// Decodes DATA indications that have been received. Returns the data along 
    /// with the address it has been received from.
    pub async fn receive_data(&self, decoded: stun_codec::Message<stun_codec::rfc5766::Attribute>) -> Result<Option<(Vec<u8>, SocketAddr)>, StunTurnErrors> {
        let peer = decoded.get_attribute::<XorPeerAddress>();
        let data = decoded.get_attribute::<Data>();
        
        if peer.is_some() && data.is_some(){
            return Ok(Some((data.unwrap().data().to_vec(), peer.unwrap().address())))
        }
        
        Ok(None)
    }
    
    /// Sends a request to the allocation to create or update a permission.
    pub async fn request_permission(&self, alloc: SocketAddr, socket: &UdpSocket) -> Result<(), StunTurnErrors> {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

        let message = Message::<T>::new(MessageClass::Request, CREATE_PERMISSION, TransactionId::new(random_bytes));

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message.clone())?;
        socket.send_to(&bytes, alloc).await?;

        Ok(())
    }

}
