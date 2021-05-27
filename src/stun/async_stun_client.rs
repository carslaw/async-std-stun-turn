use stun_codec::{MessageDecoder, MessageEncoder};
use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::rfc5389::attributes::*;
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, TransactionId};
use std::time::Duration;
use async_std::{
    net::{SocketAddr, UdpSocket},
};
use stun_codec::rfc5389::errors as stun_error;
use stun_codec::Attribute as A;
use stun_codec::convert::TryAsRef;

use crate::error::StunTurnErrors;

/// Basic send function that was created as basis for the client.
/// // Not needed in library
async fn send(message: Vec<u8>, local: &str, remote: &str) -> Result<(), StunTurnErrors> {
    let server = UdpSocket::bind(local).await?;

    server.send_to(&message, remote).await?;

    Ok(())

}

/// Basic receive function that was created as basis for the client.
// Not needed in library
async fn recv(address: &str) -> Result<Vec<u8>, StunTurnErrors> {
    let server = UdpSocket::bind(address).await?;

    let mut buf = vec![0;1024];
    server.recv(&mut buf).await?;

    Ok(buf)

}

/// The StunClient struct is used to represent a STUN client.

/// The functions defined for this struct are based on the synchronous functions used in 
/// the rust-stunclient library (https://github.com/vi/rust-stunclient). 

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StunClient{
    // Timeout of operation. Number of times to retransmit
    pub timeout: u128,
    // How often the binding requests are repeated
    pub retry_interval: Duration,
    // STUN server address
    pub socket: SocketAddr,
    // `SOFTWARE` attribute value in binding request
    pub software: Option<&'static str>,
    // Allows any other known attributes to be sent to the server
    pub attributes: Option<Vec<Attribute>>,
    pub password: Option<&'static str>
}


impl StunClient {
    /// Creates a StunClient object with default values for STUN.
    pub fn new(socket: SocketAddr) -> Self {
        StunClient {
            timeout: 7,
            retry_interval: Duration::from_millis(500),
            socket,
            software: Some("Default Rust Stun"),
            attributes: None,
            password: None
        }
    }

    /// Creates a message with the given attributes and encodes as bytes. These can be sent to a STUN or TURN server.
    /// Returns these bytes to be sent.
    pub fn binding(&self) -> Result<Vec<u8>, StunTurnErrors> {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

        let mut message = Message::new(MessageClass::Request, BINDING, TransactionId::new(random_bytes));

        // Software attribute always has to be added
        if let Some(s) = self.software {
            message.add_attribute(Attribute::Software(Software::new(
                s.to_owned(),
            )?));
        }

        // Temporary value to test whether long or short term credentials are being used.
        let mut realm = Realm::new(String::from("test")).unwrap(); 

        // adds given attributes to the message
        if self.attributes.is_some() {
            for a in self.attributes.clone().unwrap() {
                let b = a.clone();
                message.add_attribute(a);
                
                if b.get_type().as_u16() == Realm::CODEPOINT {
                    // Update realm value if it's included
                    realm = (*TryAsRef::<Realm>::try_as_ref(&b).unwrap()).clone();
                } else if b.get_type().as_u16() == Username::CODEPOINT {
                    // Create MessageIntegrity attributes and nonces depending on what type 
                    // of credential the client is sending
                    let username = &*TryAsRef::<Username>::try_as_ref(&b).unwrap();
                    let mut temp_username = (*username.name()).split(' ');
                    let user = temp_username.next().unwrap();
                    let pass = temp_username.next().unwrap();
                    
                    if !user.is_empty() && *realm.text() == *("test") {
                        message.add_attribute(Attribute::MessageIntegrity(MessageIntegrity::new_short_term_credential(&message, pass).unwrap())); 
                    } else if !user.is_empty() && *realm.text() != *("test") {
                        message.add_attribute(Attribute::MessageIntegrity(MessageIntegrity::new_long_term_credential(&message, &username, &realm, pass).unwrap()));
                        message.add_attribute(Attribute::Nonce(Nonce::new(String::from("This should be a proper nonce value")).unwrap())); // Need to figure out proper form of nonce values. 
                    }
                    continue;
                }
                
            }
        }

        // Encode the message as bytes
        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;
        Ok(bytes)
    }


    /// Decodes the address returned by the STUN server. This address will be returned by the function. 
    /// Other attributes are printed or returned as an error.
    pub fn decode_address(&self, buf: &[u8]) -> Result<Option<SocketAddr>, StunTurnErrors> {
        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder
            .decode_from_bytes(buf)?
            .map_err(|_| format!("Broken STUN reply"))?;

        for attr in decoded.attributes() {
            match attr.get_type().as_u16() { 
                MessageIntegrity::CODEPOINT => {
                    if (*TryAsRef::<MessageIntegrity>::try_as_ref(attr).unwrap()).check_short_term_credential(self.password.unwrap()).is_err() {
                        println!("Message failed integrity check");
                        return Ok(None)
                    }
                },
                _ => continue
            }
        }
        for attr in decoded.attributes() {
            match attr.get_type().as_u16() {
                XorMappedAddress::CODEPOINT => { 
                    let external_addr1 = decoded.get_attribute::<XorMappedAddress>().map(|x|x.address());
                    let external_addr2 = decoded.get_attribute::<XorMappedAddress>().map(|x|x.address());
                    if !external_addr1.unwrap().is_ipv4() {
                        format!("Returned wrong address family");
                    }
                    let external_addr = external_addr1.or(external_addr2);
                    let external_addr = external_addr.ok_or_else(||format!("No XorMappedAddress in STUN reply"))?;
                    return Ok(Some(external_addr))
                },
                ErrorCode::CODEPOINT => {     
                    let e = (*TryAsRef::<ErrorCode>::try_as_ref(attr).unwrap()).clone();
                    let a = self.attributes.clone();
                    if e.code() == 438 {
                        let n = decoded.get_attribute::<Nonce>().unwrap().clone();
                        a.unwrap().push(Attribute::Nonce(n));
                    }
                    println!("Error: {:?} occured", attr);
                    match e.code() {
                        stun_error::BadRequest::CODEPOINT => {
                            return Err(StunTurnErrors::BadRequest)
                        },
                        stun_error::ServerError::CODEPOINT => {
                            return Err(StunTurnErrors::ServerError)
                        },
                        stun_error::StaleNonce::CODEPOINT => {
                            return Err(StunTurnErrors::StaleNonce)
                        },
                        stun_error::TryAlternate::CODEPOINT => {
                            return Err(StunTurnErrors::TryAlternate)
                        },
                        stun_error::Unauthorized::CODEPOINT => {
                            return Err(StunTurnErrors::Unauthorized)
                        },
                        stun_error::UnknownAttribute::CODEPOINT => {
                            return Err(StunTurnErrors::UnknownAttribute)
                        },
                        _ => return Err(StunTurnErrors::NotStunTurnError)
                    }
                    
                }, 
                Software::CODEPOINT => continue,
                UnknownAttributes::CODEPOINT => {
                    println!("These unknown attributes were found: {:?}", attr);
                    return Err(StunTurnErrors::UnknownAttribute)
                },
                _ => {
                    println!("Something else happened: {:?}", attr);  
                }
            }
        }
        Ok(None)

        
    }

}


