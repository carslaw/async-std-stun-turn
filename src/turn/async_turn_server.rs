// use crate::stun::async_stun_server;
use stun_codec::{MessageDecoder, MessageEncoder};
use bytecodec::{DecodeExt, EncodeExt, Error};
use stun_codec::rfc5389::attributes::*;
use stun_codec::rfc5766::attributes::*;
use stun_codec::rfc5766::{methods::*, Attribute as T};


use crate::turn::async_turn_client::FiveTuple;
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, TransactionId};
use std::time::Duration;
use async_std::{
    net::{SocketAddr, UdpSocket, ToSocketAddrs},
};
use async_std::io;

use std::time::Instant;
use stun_codec::convert::TryAsRef;
use crate::error::StunTurnErrors;

/// Represents a TURN server that may create an manage allocations.
pub struct TurnServer {
    pub socket: SocketAddr,
    pub username: Option<Username>,
    pub usr: Option<&'static str>,
    pub pas: Option<&'static str>,
    pub software: Option<&'static str>,
    pub allocations: Option<Vec<(SocketAddr, SocketAddr)>>,
    pub max_lifetime: u64,
    pub client_lifetime: Option<Duration>,
    pub realm: Option<Realm>,
    pub curr_trans_id: Option<TransactionId>
}

/// Represents an allocation on a TURN server.
pub struct Allocation {
    pub local : SocketAddr,
    pub remote : SocketAddr,
    pub server : TurnServer,
    pub socket: UdpSocket,
    pub permissions : Option<Vec<(SocketAddr, Instant)>>,
}

impl Allocation {

    /// Runs the allocation server so that it listens for incoming data, refresh or permission requests.
    pub async fn listen(&mut self) -> Result<(), StunTurnErrors> {
        let mut data_wait = false;
        
        let mut temp_addr: SocketAddr = "0.0.0.0:4002".parse().unwrap();
        let mut temp_ftup = FiveTuple{
            local: Some(self.local),
            remote: Some(self.remote),
            protocol: 17,
        };
        let mut addr : SocketAddr = "0.0.0.0:0".parse().unwrap();

        loop {
            let mut buf = [0; 256];

            if data_wait {
                let b = "Some data".as_bytes();
                let bytes = self.relay_data(temp_addr, b).await?;
                println!("Sending data indication");
                self.socket.send_to(&bytes, temp_ftup.remote.unwrap()).await?;
                data_wait = false;
                continue;
            }

            // Checks permissions are still valid
            if self.permissions.is_some() {
                for permission in self.permissions.clone().unwrap() {
                    if permission.0 == addr {
                        if Instant::now().duration_since(permission.1) >= Duration::from_secs(300) {
                            let index = self.server.allocations.clone().unwrap().iter().position(|x| *x == (self.local, self.remote)).unwrap();
                            self.server.allocations.clone().unwrap().remove(index);
                            return Ok(())
                        }
                    }
                }
            }
            
            let mut len : usize = 0;

            // Repeat loop after 10 seconds without data. Allows server to continue checking the permissions and lifetimes.
            let recv_timeout = io::timeout(Duration::from_secs(10), async {
                let (l, a) = self.socket.recv_from(&mut buf[..]).await?;
                len = l;
                addr = a;
                Ok((l, a))
            }).await;

            match recv_timeout {
                Ok(_x) => (),
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    ();
                },
                Err(e) => Err(e)?,
            }

            if len == 0 {
                continue
            }

            let buf = &buf[0..len];
            let connection = FiveTuple {
                local: Some(self.local),
                remote: Some(self.remote),
                protocol: 17,
            };

            // If raw data was received on the last iteration then send this to the client.
            if data_wait {
                let bytes = self.relay_data(addr, buf).await?;
                println!("Sending data indication");
                self.socket.send_to(&bytes, connection.remote.unwrap()).await?;
                data_wait = false;
                continue;
            }
            
            let check = self.server.check_message(buf).await?;
            let mut refresh = false;

            // If an error thrown when checking message, send error response and close allocation.
            if check.0.is_some() {
                let response = self.server.form_response(connection.clone(), check.0.clone(), self.remote, false).await?;
               
                self.socket.send_to(&response, addr).await?;
                let mut a = self.server.allocations.clone().unwrap();
                let index = a.iter().position(|x| *x == (self.local, self.remote)).unwrap();
                a.remove(index);
                self.server.allocations = Some(a);
                return Ok(())
            }

            // If refresh request received, attempt to refresh the allocation. Stop allocation if refresh had lifetime of zero.
            if check.1.is_some() {
                if check.1.unwrap() {
                    refresh = self.server.refresh(buf, (self.local, self.remote)).await?;
                    if !refresh {
                        return Ok(())
                    }
                }
            }
            
            // If a SEND indication was received, send the data to the peer.
            if check.2.is_some() {
                if check.2.unwrap() {
                    let data_handle = self.data_handling(buf).await?.unwrap();
                    data_wait = data_handle.0;
                    let data: &[u8] = &data_handle.1;
                    println!("Sending data to peer");
                    self.socket.send_to(data, data_handle.2).await?;
                }
            }

            // If a permission request was received, create a new permission or update an existing one. Then send a response to the client.
            if check.3.is_some() {
                if check.3.unwrap() {
                    println!("Permission requests");
                    let perm_success = self.create_permission(addr).await?;
                    self.socket.send_to(&perm_success, addr).await?;
                }
            }

            // If lifetime has been updated then send a REFRESH success response to the client.
            if refresh {
                let response = self.server.form_response(connection.clone(), check.0, self.remote, refresh).await?;
                println!("About to send refresh response");
                self.socket.send_to(&response, addr).await?;
            }

            // Save the address and FiveTuple, that has been changed, for the next iteration.
            temp_addr = addr;
            temp_ftup = connection.clone();

        }
    }

    /// Creates a new permission or updates an existing permission. Returns an encoded message to confirm this to the client.
    pub async fn create_permission(&mut self, peer: SocketAddr) -> Result<Vec<u8>, Error> {
        let mut self_perms = self.permissions.clone();
        if self_perms.is_none() {
            println!("Creating a new permission");
            self_perms = Some(vec!((peer, Instant::now())));
            self.permissions = self_perms;
        } else {
            let mut unwrapped = self_perms.unwrap();
            let index = self.permissions.clone().unwrap().iter().position(|x| x.0 == peer);

            if index.is_some() {
                unwrapped.remove(index.unwrap());
                println!("Updating permission");
            }
            println!("Adding permission");
            unwrapped.push((peer, Instant::now()));
            self.permissions = Some(unwrapped);
        }

        let message = Message::<T>::new(MessageClass::SuccessResponse, CREATE_PERMISSION, self.server.curr_trans_id.unwrap());
        let mut encoder = MessageEncoder::new();

        let bytes = encoder.encode_into_bytes(message)?;

        Ok(bytes)
    }

    /// Takes a SEND indication message from the client and extracts the data and the address of the peer. 
    /// It returns these to allow the data to be sent to the peer.
    pub async fn data_handling(&mut self, message: &[u8]) -> Result<Option<(bool, Vec<u8>, SocketAddr)>, StunTurnErrors> {
        let mut t_decoder = MessageDecoder::<T>::new();
        let t_decoded = t_decoder.decode_from_bytes(&message)?.map_err(Error::from)?;

        if t_decoded.method() == SEND {
            let peer = t_decoded.get_attribute::<XorPeerAddress>().unwrap().address();
            let buf = t_decoded.get_attribute::<Data>().unwrap().data();
            println!("Extracted data and address of peer");
            return Ok(Some((true, buf.to_vec(), peer)))
        } else {
            // Discard
            return Ok(None)
        }      
    }

    /// Creates and encodes a DATA indication that contains the data from a peer and it's address. It returns this as encoded bytes.
    pub async fn relay_data(&mut self, received_addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>, Error> {
        
        // For future:
        // Check permissions first
        // If relay permitted check channels

        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; 12]>();

        let mut message = Message::new(MessageClass::Indication, DATA, TransactionId::new(random_bytes));

        message.add_attribute(T::XorPeerAddress(XorPeerAddress::new(received_addr)));
        message.add_attribute(T::Data(Data::new(data.to_vec()).unwrap()));

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;
        
        Ok(bytes)
    }
}

impl TurnServer {

    /// Updates the allocation storage and refreshes the allocation if requested. Returns a boolean to represent whether the allocation has been refreshed.
    pub async fn refresh_check(&mut self, to_refresh: Option<bool>, connection: FiveTuple, buf: &[u8]) -> Result<bool, Error> {
        let mut refresh = false;
        let mut allocs : Vec<(SocketAddr, SocketAddr)>;
        if self.allocations.is_some() {
            allocs = self.allocations.clone().unwrap();
            if allocs.contains(&(connection.local.unwrap(), connection.remote.unwrap())) {
                self.refresh(buf, (connection.local.unwrap(), connection.remote.unwrap())).await?;
                refresh = true;
            }
            allocs.push((connection.local.unwrap(), connection.remote.unwrap()));
        } else {
            allocs = vec!((connection.local.unwrap(), connection.remote.unwrap()));
        }
        self.allocations = Some(allocs);

        if to_refresh.is_some() {
            if to_refresh.unwrap() {
                self.refresh(buf, (connection.local.unwrap(), connection.remote.unwrap())).await?;
                refresh = true;
            }
        }
        Ok(refresh)
    }
    
    /// Refreshes the allocation with the either the requested lifetime or the maximum lifetime. 
    /// If a lifetime of 0 is received then the allocation is closed. 
    /// Returns a boolean to represent if the allocation has been refreshed or closed.
    pub async fn refresh(&mut self, message: &[u8], allocation: (SocketAddr, SocketAddr)) -> Result<bool, Error> {
        let mut t_decoder = MessageDecoder::<T>::new();
        let t_decoded = t_decoder.decode_from_bytes(&message)?.map_err(Error::from)?;

        let mut a = self.allocations.clone().unwrap();


        if t_decoded.method() == REFRESH {
            let l = t_decoded.get_attribute::<Lifetime>();
            if l.is_some() {
                if l.unwrap().lifetime().as_secs() == 0 {
                    let index = a.iter().position(|x| *x == allocation).unwrap();
                    a.remove(index);
                    self.allocations = Some(a);
                    return Ok(false)
                    // change local to none
                    // remove allocation
                } else {
                    if l.unwrap().lifetime().as_secs() < self.max_lifetime {
                        self.client_lifetime = Some(l.unwrap().lifetime());
                    } else {
                        self.client_lifetime = Some(Duration::from_secs(self.max_lifetime));
                    }
                }
            }
        }

        Ok(true)
    }

    /// Chooses a port in the range between 49152 and 65534 as required by TURN.
    /// Returns the new address along with it's UDP binding.
    pub async fn choose_port(&mut self) -> Result<(SocketAddr, Option<UdpSocket>), StunTurnErrors> {
        let mut i : u16 = 49152;
        // let mut alloc : UdpSocket;
        while i <= 65534 {
            self.socket.set_port(i);
            let alloc = UdpSocket::bind(self.socket).await;
            match alloc {
                Ok(addr) => {
                    println!("Address from port is {:?}", addr);
                    return Ok((self.socket, Some(addr)))
                },
                Err(_e) => i += 1,
            };  
            
        }
        Ok((self.socket, None))
    }

    /// Decodes and checks a message. Uses two decoders to check for the STUN and TURN attributes.
    /// Returns A combination of an error code or three booleans. These represent that either a 
    /// REFRESH request, CREATE_PERMISSION request or SEND indication has been received. 
    pub async fn check_message(&mut self, message: &[u8]) -> Result<(Option<ErrorCode>, Option<bool>, Option<bool>, Option<bool>), StunTurnErrors> {
        use stun_codec::Attribute as A;

        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder.decode_from_bytes(&message)?.map_err(Error::from)?; 

        let mut t_decoder = MessageDecoder::<T>::new();
        let t_decoded = t_decoder.decode_from_bytes(&message)?.map_err(Error::from)?;

        let mut integrity = false;
        let mut username = false;
        let mut realm_bool = false;
        let mut auth = false;
        let mut req_trans = false;

        let mut realm = Realm::new(String::from("")).unwrap();
        let mut nonce = Nonce::new(String::from("")).unwrap();
        let mut user = Username::new(String::from("")).unwrap();
        let mut cli_usr: &str = "";
        let mut cli_pas: &str = "";
        
        // Prints unknown attributes. These should be handled like the STUN server.
        for u in decoded.unknown_attributes() {
            println!("{:?}", u);
        } 

        if t_decoded.method() == REFRESH || decoded.method() == REFRESH {
            println!("REFRESH method received");
            self.curr_trans_id = Some(t_decoded.transaction_id());
            return Ok((None, Some(true), None, None));
        }

        if t_decoded.method() == SEND || decoded.method() == SEND {
            println!("SEND method received");
            self.curr_trans_id = Some(t_decoded.transaction_id());
            return Ok((None, None, Some(true), None));
        }

        if t_decoded.method() == CREATE_PERMISSION || decoded.method() == CREATE_PERMISSION {
            println!("CREATE_PERMISSION request received");
            self.curr_trans_id = Some(t_decoded.transaction_id());
            return Ok((None, None, None, Some(true)));
        }
        
        // TURN attribute handling. Add more attribute handling in the future.
        for attr in t_decoded.attributes() {
            match attr.get_type().as_u16() {
                RequestedTransport::CODEPOINT => {
                    self.curr_trans_id = Some(t_decoded.transaction_id());
                    // Don't allow non-UDP traffic. This should be changed to the protocol used by the connection if support for more transport protocols is added.
                    if (*TryAsRef::<RequestedTransport>::try_as_ref(attr).unwrap()).protocol() != 17 {
                        return Ok((Some(ErrorCode::new(400, String::from("Bad Request")).unwrap()), None, None, None))
                    }
                    req_trans = true;
                },
                Lifetime::CODEPOINT => {
                    self.curr_trans_id = Some(t_decoded.transaction_id());
                    let life = (*TryAsRef::<Lifetime>::try_as_ref(attr).unwrap()).lifetime();
                    if life.as_secs() < self.max_lifetime {
                        self.client_lifetime = Some(life);
                    }
                }
                _ => {
                    self.curr_trans_id = Some(t_decoded.transaction_id());
                    continue
                }
            }
        }

        // STUN attribute handling.
        for attr in decoded.attributes() {
            match attr.get_type().as_u16() {
                ErrorCode::CODEPOINT => if integrity {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    continue
                } else {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    return Ok((Some((*TryAsRef::<ErrorCode>::try_as_ref(attr).unwrap()).clone()), None, None, None))
                },
                Username::CODEPOINT => if integrity {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    continue
                } else {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    username = true;
                    if self.username != None {
                        user = (*TryAsRef::<Username>::try_as_ref(attr).unwrap()).clone();
                        let mut temp = user.name().split(' ');
                        cli_usr = temp.next().unwrap();
                        cli_pas = temp.next().unwrap();
                        if user != self.username.clone().unwrap() {
                            return Ok((Some(ErrorCode::new(401, String::from("Unauthorized")).unwrap()), None, None, None))
                        }
                    }
                    
                },
                Realm::CODEPOINT => {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    if integrity {
                        continue
                    } else {
                        if self.username != None {
                            realm_bool = true;
                            realm = (*TryAsRef::<Realm>::try_as_ref(attr).unwrap()).clone();
                            if realm != self.realm.clone().unwrap() {
                                return Ok((Some(ErrorCode::new(401, String::from("Unauthorized")).unwrap()), None, None, None))

                            }
                        }
                    }
                },
                // Need to check for staleness. Nonces never handled properly.
                Nonce::CODEPOINT => {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    if integrity {
                        continue
                    } else {
                        nonce = (*TryAsRef::<Nonce>::try_as_ref(attr).unwrap()).clone();  
                    }
                },
                
                MessageIntegrity::CODEPOINT => {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    auth = true;
                    if realm_bool && username{
                        if (*TryAsRef::<MessageIntegrity>::try_as_ref(attr).unwrap()).check_long_term_credential(&user, &realm, self.pas.unwrap()).is_err() {
                            return Ok((Some(ErrorCode::new(401, String::from("Unauthorized")).unwrap()), None, None, None))
                            
                        }
                    }
                },

                _ => {
                    self.curr_trans_id = Some(decoded.transaction_id());
                    continue
                }
            }
        }
        if !auth {
            return Ok((Some(ErrorCode::new(401, String::from("Unauthorized")).unwrap()), None, None, None))

        }

        // Parts of TURN messages that can still be checked in future. 
        // Check requested transport attr (should)
        // Don't fragment check (should)
        // Reservation-token check (should)
        // requested_address_Family check (Should)
        // Even port check (should)
        // additional address checck (should)
        // reservation/even port checks

        Ok((None, None, None, None))
    }

    /// Forms responses messages either as an error response or as a success response. 
    /// The success responses can contain lifetime values and/or the relayed and server reflexive addresses.
    /// Returns encoded bytes that can be sent to the client.
    pub async fn form_response(&mut self, connection: FiveTuple, error: Option<ErrorCode>, remote: SocketAddr, refresh: bool) -> Result<Vec<u8>, StunTurnErrors> {

        if error.is_some() {
            let mut error_message = Message::new(MessageClass::ErrorResponse, BINDING, self.curr_trans_id.unwrap());
            let e = error.clone();
            error_message.add_attribute(Attribute::ErrorCode(error.unwrap()));
            
            if let Some(s) = self.software {
                error_message.add_attribute(Attribute::Software(Software::new(s.to_owned(),)?));
            }
            if e.unwrap().code() == 401 {
                // Nonce and realm values are not properly represented.
                error_message.add_attribute(Attribute::Nonce(Nonce::new(String::from("This should be a proper nonce value")).unwrap())); 
                error_message.add_attribute(Attribute::Realm(Realm::new(String::from("This should be a proper realm value")).unwrap()));
            } 
            let mut encoder = MessageEncoder::new();
            let bytes = encoder.encode_into_bytes(error_message)?;

            Ok(bytes)
        } else {
            let mut message = Message::new(MessageClass::SuccessResponse, BINDING, self.curr_trans_id.unwrap());

            // Send a REFRESH success response
            if refresh && self.client_lifetime.is_some(){
                let mut message = Message::new(MessageClass::SuccessResponse, REFRESH, self.curr_trans_id.unwrap());
                message.add_attribute(T::Lifetime(Lifetime::new(self.client_lifetime.unwrap()).unwrap()));
            } else {
                // Send an allocation success response
                message.add_attribute(T::XorRelayAddress(XorRelayAddress::new(connection.local.unwrap())));
                message.add_attribute(T::XorPeerAddress(XorPeerAddress::new(remote))); // This contains the server reflexive address, not a peer address.
                if self.client_lifetime.is_some() {
                    if self.client_lifetime.unwrap().as_secs() < self.max_lifetime {
                        message.add_attribute(T::Lifetime(Lifetime::new(self.client_lifetime.unwrap()).unwrap()));
                    }
                } else {
                    message.add_attribute(T::Lifetime(Lifetime::new(Duration::from_secs(self.max_lifetime)).unwrap()));
                
                }
            }

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;

        Ok(bytes)

        }
    }
}
