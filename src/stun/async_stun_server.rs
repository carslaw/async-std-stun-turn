use stun_codec::{MessageDecoder, MessageEncoder};
use bytecodec::{DecodeExt, EncodeExt, Error};
use stun_codec::AttributeType;
use stun_codec::rfc5389::attributes::*;
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, TransactionId};
use std::time::Duration;
use async_std::{
    net::{SocketAddr, UdpSocket, ToSocketAddrs},
};
use std::time::Instant;
use stun_codec::convert::TryAsRef;


/// An enum to represent the states of messages that are received.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageChecks {
    WellFormed,
    UnknownAttributes,
    UnreasonableLength,
    IncorrectTransactionId,
    IncorrectMagicCookie,
    IncorrectStartBits,
    Unauthorised,
    MessageIntegrity,
    UnauthorisedRealm,
    UnauthorisedLong,
}

/// Basic server that was used as basis for the STUN server.
// Not needed in library
async fn basic_server() -> Result<([u8; 32]), Error>{
    let local_addr : SocketAddr = "127.0.0.1:40001".parse().unwrap();
    
    let local = UdpSocket::bind(local_addr).await?;
    let mut buf = [0; 32];

    let mut i: i32 = 0;

    loop {
        let (_len, _addr) = match local.recv_from(&mut buf[..]).await {
            Ok(x) => x,
            Err(e) => Err(e)?,
        };
        i+=1;
    }
    println!("{:?}", buf);
    Ok(buf)
}

/// StunServer is used to represent a STUN server.
pub struct StunServer {
    pub socket: SocketAddr,
    pub transactions: Option<Vec<(TransactionId, Instant)>>,
    pub software: Option<&'static str>,
    pub username: Option<Username>,
    pub usr: Option<&'static str>, // redundant
    pub pas: Option<&'static str>, // redundant

}

impl StunServer {
    
    /// Checks that a message is well formed and checks the attributes. 
    /// Returns one of the MessageChecks values, the attribute type(either RFC 5389 or unknown) and may return an error code and transaction ID.
    pub async fn check_message(&mut self, message: &[u8]) -> Result<(MessageChecks, Vec<AttributeType>, Option<ErrorCode>, Option<TransactionId>), Error>{
        let rfc5389_attrs = Vec::<AttributeType>::new();
    
        if message.len() > 2000 {
            return Ok((MessageChecks::UnreasonableLength, rfc5389_attrs, None, None))
        }

        use stun_codec::Attribute as A;

        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder.decode_from_bytes(&message)?.map_err(Error::from)?; 
       
        let mut integrity = false;
        let mut username = false;
        let mut realm_bool = false;

        // Initial instances of these variables
        let mut realm = Realm::new(String::from("test")).unwrap();
        let mut nonce = Nonce::new(String::from("")).unwrap();
        let mut user = Username::new(String::from("")).unwrap();
        let mut cli_usr: &str = "";
        let mut cli_pas: &str = "";
        
        for attr in decoded.attributes() {
            match attr.get_type().as_u16() {
                ErrorCode::CODEPOINT => if integrity {
                    continue
                } else {
                    return Ok((MessageChecks::UnreasonableLength, rfc5389_attrs, Some((*TryAsRef::<ErrorCode>::try_as_ref(attr).unwrap()).clone()), Some(decoded.transaction_id())))
                },
                Username::CODEPOINT => if integrity {
                    continue
                } else {
                    username = true;
                    if self.username != None {
                        user = (*TryAsRef::<Username>::try_as_ref(attr).unwrap()).clone();
                        let mut temp = user.name().split(' ');
                        cli_usr = temp.next().unwrap();
                        cli_pas = temp.next().unwrap();

                    }
                },
                Realm::CODEPOINT => {
                    if integrity {
                        continue
                    } else {
                        realm_bool = true;
                        realm = (*TryAsRef::<Realm>::try_as_ref(attr).unwrap()).clone();
                    }
                },
                // Needs to be checked for staleness
                Nonce::CODEPOINT => {
                    if integrity {
                        continue
                    } else {
                        nonce = (*TryAsRef::<Nonce>::try_as_ref(attr).unwrap()).clone();
                    }
                },
                MessageIntegrity::CODEPOINT => {
                    integrity = true;
                    if !username && decoded.class() == MessageClass::Request {
                        return Ok((MessageChecks::Unauthorised, rfc5389_attrs, Some(ErrorCode::new(400, String::from("Bad Request")).unwrap()), Some(decoded.transaction_id())))
                    } else if !username && decoded.class() == MessageClass::Indication {
                        continue
                    } else if cli_usr == (self.usr).clone().unwrap() {
                        self.add_transaction_id(decoded.transaction_id());
                    } else if cli_usr != (self.username).clone().unwrap().name() && realm_bool {
                        return Ok((MessageChecks::Unauthorised, rfc5389_attrs, Some(ErrorCode::new(401, String::from("Unauthorised")).unwrap()), Some(decoded.transaction_id())))
                    } else if realm_bool && (!username || nonce.value() == "") {
                        return Ok((MessageChecks::Unauthorised, rfc5389_attrs, Some(ErrorCode::new(400, String::from("Bad Request")).unwrap()), Some(decoded.transaction_id())))
                    } else if realm_bool {
                        if cli_usr != (self.username).clone().unwrap().name() {
                            return Ok((MessageChecks::Unauthorised, rfc5389_attrs, Some(ErrorCode::new(401, String::from("Unauthorised")).unwrap()), Some(decoded.transaction_id())))
                        }
                        if user.name() != "" {
                            if (*TryAsRef::<MessageIntegrity>::try_as_ref(attr).unwrap()).check_long_term_credential(&user, &realm, self.pas.unwrap()).is_err() {
                                return Ok((MessageChecks::UnauthorisedLong, rfc5389_attrs, Some(ErrorCode::new(401, String::from("Unauthorised")).unwrap()), Some(decoded.transaction_id())))
                            }
                        }
                        
                    }
                    if (*TryAsRef::<MessageIntegrity>::try_as_ref(attr).unwrap()).check_short_term_credential(self.pas.unwrap()).is_err() {
                        if decoded.class() == MessageClass::Request {
                            return Ok((MessageChecks::Unauthorised, rfc5389_attrs, Some(ErrorCode::new(401, String::from("Unauthorised")).unwrap()), Some(decoded.transaction_id())))
                        } else if decoded.class() == MessageClass::Indication {
                            continue
                        }
                    }
                }, 
                // Fingerprint value needs checked    
                _ => continue,
            }
        }

        if !integrity && username && decoded.class() == MessageClass::Request {
            return Ok((MessageChecks::Unauthorised, rfc5389_attrs, Some(ErrorCode::new(400, String::from("Bad Request")).unwrap()), Some(decoded.transaction_id())))
        } 

        if !integrity && realm_bool {
            return Ok((MessageChecks::UnauthorisedRealm, rfc5389_attrs, Some(ErrorCode::new(401, String::from("Unauthorized")).unwrap()), Some(decoded.transaction_id())))
        }

        // Return any unknown attributes along with error message
        let mut unk_attrs = Vec::<AttributeType>::new();
        for u_attr in decoded.unknown_attributes() {
            if u_attr.get_type().is_comprehension_required() {
                unk_attrs.push((*u_attr).clone().get_type());
            }
        }
        if !unk_attrs.is_empty() {
            let err = ErrorCode::new(420, String::from("Unknown Attribute")).unwrap();
            return Ok((MessageChecks::UnknownAttributes, unk_attrs, Some(err), Some(decoded.transaction_id())));
        }

        

        // Remember transaction ID's to prevent retransmissions
        if decoded.class() == MessageClass::SuccessResponse || decoded.class() == MessageClass::ErrorResponse {
            self.refresh_transaction_ids();
            for id in self.transactions.as_ref().unwrap() {
                if decoded.transaction_id() != id.0 {
                    return Ok((MessageChecks::IncorrectTransactionId, rfc5389_attrs, None, Some(decoded.transaction_id())));
               }
            }
        }

        if integrity {
            return Ok((MessageChecks::MessageIntegrity, rfc5389_attrs, None, Some(decoded.transaction_id())))
        }
        Ok((MessageChecks::WellFormed, rfc5389_attrs, None, Some(decoded.transaction_id())))
    }   

    /// Creates a new message to send to the client in response. Adds either error messages or the server reflexive address to the message. 
    /// Returns a mesaage encoded as bytes that can be sent to the client.
    pub async fn form_response(&self, addr: SocketAddr, check: MessageChecks, attrs: Vec<AttributeType>, error: Option<ErrorCode>, transaction: TransactionId) -> Result<Vec<u8>, Error> {
        let mut message = Message::new(MessageClass::SuccessResponse, BINDING, transaction);

        if error.is_some() {
            message = Message::new(MessageClass::ErrorResponse, BINDING, transaction);
            let e = error.clone();
            let e2 = error.clone();
            let e3 = error.clone();
            message.add_attribute(Attribute::ErrorCode(error.unwrap()));
            
            if let Some(s) = self.software {
                message.add_attribute(Attribute::Software(Software::new(s.to_owned(),)?));
            }
            if e.unwrap().code() == 401 && check == MessageChecks::UnauthorisedRealm {
                message.add_attribute(Attribute::Nonce(Nonce::new(String::from("This should be a proper nonce value")).unwrap())); // Need to figure out proper form of nonce values. Should be domain name of server provider??
            }
            if e2.unwrap().code() == 420 {
                message.add_attribute(Attribute::UnknownAttributes(UnknownAttributes::new(attrs)))
            }
            if e3.unwrap().code() == 401 && check == MessageChecks::UnauthorisedLong {
                message.add_attribute(Attribute::Nonce(Nonce::new(String::from("This should be a proper nonce value")).unwrap())); // Need to figure out proper form of nonce values. Should be domain name of server provider??
                message.add_attribute(Attribute::Realm(Realm::new(String::from("This should be a proper realm value")).unwrap())); // Need to figure out proper form of realm values. 
            }
        }

        // Rest of MessageCheck states should be matched in future
        match check {
            MessageChecks::WellFormed => {
                message.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));
                if let Some(s) = self.software {
                    message.add_attribute(Attribute::Software(Software::new(s.to_owned(),)?));
                }
            },
            MessageChecks::MessageIntegrity => {
                message.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));
                if let Some(s) = self.software {
                    message.add_attribute(Attribute::Software(Software::new(s.to_owned(),)?));
                }
                message.add_attribute(Attribute::MessageIntegrity(MessageIntegrity::new_short_term_credential(&message, self.pas.unwrap()).unwrap()));
            },
            _ => {
                let error = ErrorCode::new(400, "Bad Request".to_owned()).unwrap();
                message.add_attribute(Attribute::ErrorCode(error));
                if let Some(s) = self.software {
                    message.add_attribute(Attribute::Software(Software::new(s.to_owned(),)?));
                }
            }

        }

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;
        Ok(bytes)
    }

    /// Updates or removes transaction IDs after 40 seconds.
    pub fn refresh_transaction_ids(&mut self) {
        let i = 0;
        let mut ids = self.transactions.as_ref().unwrap().clone();
        while i < ids.len() {
            if ids[i].1.elapsed() > Duration::from_secs(40) {
                ids.remove(i);
            }
        }
        self.transactions = Option::from(ids);
    }

    /// Saves transaction IDs to prevent any retransmissions.
    pub fn add_transaction_id(&mut self, id: TransactionId) {
        if self.transactions.is_some() {
            let mut ids = self.transactions.as_ref().unwrap().clone();
            ids.push((id, Instant::now()));
            self.transactions = Option::from(ids);
        } else {
            let ids = vec!((id, Instant::now()));
            self.transactions = Option::from(ids);
        }
        
    }

}

