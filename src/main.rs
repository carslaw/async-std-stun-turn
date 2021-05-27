//! Example servers for STUN and TURN.
//! 
//! Running this file allows the user to choose one from a 
//! "stun", "turn" or "peer" server when this is typed.
//! 
//! The peer is a work in progress and may not work.
//! 

use async_std_stun_turn::stun::async_stun_server::StunServer;
use async_std::net::ToSocketAddrs;
use async_std::net::UdpSocket;
use async_std::net::SocketAddr;
use async_std::io;
use std::time::Duration;
use stun_codec::rfc5389::attributes::*;
use async_std_stun_turn::turn::async_turn_server::*;
use async_std_stun_turn::turn::async_turn_client::*;
use stun_codec::rfc5389::Attribute as S;
use async_std_stun_turn::error::StunTurnErrors;
use std::io::stdin;

#[async_std::main]
pub async fn main() {
    let mut st = String::new();
    stdin().read_line(&mut st);
    if let Some('\n')=st.chars().next_back() {
        st.pop();
    }
    if let Some('\r') = st.chars().next_back() {
        st.pop();
    }
    
    if st == "stun" {
        let _s = stun_server_test().await;
    } else if st == "turn" {
        let _t = turn_server().await;
    } else if  st == "peer" {
        let _p = peer().await;
    } 
}

/// Runs a STUN server on port 3478 using the example authentication
pub async fn stun_server_test() ->Result<(), StunTurnErrors> {
    let mut server = StunServer{
        socket: "0.0.0.0:3478".to_socket_addrs().await?.find(|x|x.is_ipv4()).unwrap(),
        software: Some("STUN response"),
        username: Some(Username::new(String::from("username Pass")).unwrap()),
        transactions: None,
        usr: Some("username"),
        pas: Some("Pass"),
    };

    let local = UdpSocket::bind(server.socket).await.unwrap();
    let mut buf = [0; 256];

    loop {
        let (len, addr) = match local.recv_from(&mut buf[..]).await {
            Ok(x) => x,
            Err(e) => Err(e)?,
        };
        let buf = &buf[0..len];

        // After a message has been received, check it, create an appropriate response and send the response.
        let check = server.check_message(buf).await?;
        let address = server.form_response(addr, check.0, check.1, check.2, check.3.unwrap()).await?;
        local.send_to(&address, addr).await?;
    }
}

/// Runs a TURN server on port 3478 with the testing authentication.
pub async fn turn_server() -> Result<(), StunTurnErrors> {
    let mut server = TurnServer {
        socket: "0.0.0.0:3478".to_socket_addrs().await?.find(|x|x.is_ipv4()).unwrap(),
        software: Some("STUN response"),
        username: Some(Username::new(String::from("username Pass")).unwrap()), //none
        usr: Some("username"),
        pas: Some("Pass"),
        allocations: None,
        max_lifetime: 30, // this value must be greater than the lifetime_check value in tests.rs
        client_lifetime: None,
        realm: Some(Realm::new(String::from("realmtest")).unwrap()),
        curr_trans_id: None,
    };

    let local = UdpSocket::bind(server.socket).await.unwrap();
    let mut buf = [0; 256];

    loop {
        let mut len : usize = 0;
        let mut addr : SocketAddr = "0.0.0.0:0".parse().unwrap();

        // Wait for 10 seconds before continuing through loop
        let recv_timeout = io::timeout(Duration::from_secs(10), async {
            let (l, a) = local.recv_from(&mut buf[..]).await?;
            len = l;
            addr = a;
            Ok((l, a))
        }).await;

        match recv_timeout {
            Ok(_x) => (),
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                ();
            },
            Err(e) => return Err(e.into()),
        }

        if len == 0 {
            continue
        }
        
        let buf = &buf[0..len];

        // Assign an address for an allocation
        let new_alloc = server.choose_port().await.unwrap();
        
        let f = FiveTuple {
            local : Some(new_alloc.0),
            remote : Some(addr),
            protocol : 17 
        };

        // Check the message and allocations/refresh status
        let check = server.check_message(&buf).await?;
        let refresh = server.refresh_check(check.1, f.clone(), &buf).await?;

        // Create a response message containing an error or the new allocation address.
        let allocation = server.form_response(f.clone(), check.0, addr, refresh).await?;
        local.send_to(&allocation, addr).await?;
        
        // If an allocation address has been created then create an Allocation object and start it listening.
        if new_alloc.1.is_some() {
            let t = TurnServer {
                socket: server.socket,
                username: server.username.clone(),
                usr: server.usr,
                pas: server.pas,
                software: server.software,
                allocations: server.allocations.clone(),
                max_lifetime: server.max_lifetime,
                client_lifetime: server.client_lifetime,
                realm: server.realm.clone(),    
                curr_trans_id: None,
            };

            let mut a = Allocation {
                local: new_alloc.0,
                remote: f.remote.unwrap(),
                socket: new_alloc.1.unwrap(),
                server: t,
                permissions: None,
            };
            a.listen().await?;
            println!("Waiting for requests");
        }

    }

}

/// Unfinished attempt at a peer. Should function but hasn't been tested.
pub async fn peer() -> Result<(), StunTurnErrors> {
    let local_addr : SocketAddr = "0.0.0.0:50000".parse().unwrap();
     
    // let mut ta = TurnAllocation {
    //     relayed_addrs : None,
    //     ftup : FiveTuple{
    //         local : Some(local_addr),
    //         remote : Some(remote_addr),
    //         protocol : 17, 
    //     },
    //     auth : Username::new(String::from("username Pass")).unwrap(), //password, realm,  nonce
    //     expiry_time : Some(Duration::from_secs(100)),
    //     permissions : None, // Change to permisssions list
    //     // channel_binds : Vec<BINDING>
    //     data : "".as_bytes().to_vec(),
    // };

    let mut attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
    attributes.push(S::Realm(Realm::new(String::from("realmtest")).unwrap()));
    let local = UdpSocket::bind(local_addr).await?;
    let mut buf = [0; 256];
    let mut send_amount = 0;
    loop {
        let mut len : usize = 0;
        let mut addr : SocketAddr = "0.0.0.0:0".parse().unwrap();

        if send_amount >= 10 {
            return Ok(())
        }

        let recv_timeout = io::timeout(Duration::from_secs(10), async {
            let (l, a) = local.recv_from(&mut buf[..]).await?;
            len = l;
            addr = a;
            Ok((l, a))
        }).await;

        match recv_timeout {
            Ok(_x) => (),
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                ();
            },
            Err(e) => return Err(e.into()),
        }
        
        let buf = &buf[0..len];
        println!("Peer address is {:?}", addr);
        if len == 0 {
            continue
        }

        // let mut decoder = MessageDecoder::<T>::new();
        // let decoded = decoder.decode_from_bytes(&buf)?.map_err(Error::from)?;
        
        println!("Has received some data {:?}", buf);
        // let string = match str::from_utf8(buf) {
        //     Ok(v) => v,
        //     Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        // };
        // println!("{:?}", string);
        local.send_to(b"Recieved some data", addr).await?;
        send_amount += 1;
    }

    // allocate(ta, Some(peer), Some(attributes)).await?;
}