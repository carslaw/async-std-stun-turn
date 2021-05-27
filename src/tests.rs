
//! Tests demonstrating different parts of the STUN or TURN protocols.
//! 
//! These also show a way to run a STUN or TURN client. The allocate and get_actual address 
//! contain most of the code needed for a their respective client.

//! The different suites can be run using cargo t stun or cargo t turn -- --test-threads 1

use crate::stun::async_stun_client::*;
use stun_codec::rfc5389::attributes::*;
use crate::turn::async_turn_client::*;
use stun_codec::rfc5389::Attribute as S;
use async_std::{
    prelude::*,
    net::{SocketAddr, UdpSocket, ToSocketAddrs},
};
use async_std::io;
use std::time::Duration;
use std::ops::Sub;
use std::time::Instant;
use std::thread::sleep;

use crate::error::StunTurnErrors;

/// For testing that actual address is found. Replace with user's actual address.
pub static ADDR: &str = "127.0.0.1"; 

/// Remote address to be used for the tests. Setup for local use by default.
pub static REMOTE_ADDR: &str = "127.0.0.1:3478";

/// Local address to be used for the tests.
pub static LOCAL_ADDR: &str = "0.0.0.0:0";

/// Peer address to be used for the tests. Setup for local use by default.
pub static PEER: &str = "127.0.0.1:50000";



#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn turn_allocate_test() -> Result<(), StunTurnErrors> {
        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();
        let peer : SocketAddr = PEER.parse().unwrap();

        let mut ta = TurnClient {
            relayed_addrs : None,
            ftuple : FiveTuple{
                local : Some(local_addr),
                remote : Some(remote_addr),
                protocol : 17, 
            },
            auth : Username::new(String::from("username Pass")).unwrap(),
            expiry_time : Some(Duration::from_secs(100)),
            permissions : None,
            data : "initial data".as_bytes().to_vec(),
        };
        // Add attributes, which would be optional if there was no authentication.
        let mut attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
        attributes.push(S::Realm(Realm::new(String::from("realmtest")).unwrap()));

        let alloc = allocate(ta, Some(peer), Some(attributes)).await?;
        assert_eq!(alloc.1.socket.ip(), remote_addr.ip());
        Ok(assert_ne!(alloc.1.socket.port(), remote_addr.port()))
    }

    #[async_std::test]
    async fn turn_authentication_test() -> Result<(), StunTurnErrors> {
        // Tests are sleeping to allow the allocation time to close properly.
        sleep(Duration::from_secs(10));

        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();
        let peer : SocketAddr = PEER.parse().unwrap();
        let mut ta = TurnClient {
            relayed_addrs : None,
            ftuple : FiveTuple{
                local : Some(local_addr),
                remote : Some(remote_addr),
                protocol : 17, 
            },
            auth : Username::new(String::from("username Pass")).unwrap(),
            expiry_time : Some(Duration::from_secs(100)),
            permissions : None, 
            data : "Hello peer test".as_bytes().to_vec(),
        };

        let mut attributes = vec!(S::Username(Username::new(String::from("wrong Pass")).unwrap()));
        attributes.push(S::Realm(Realm::new(String::from("realm")).unwrap()));

        let alloc = allocate(ta, Some(peer), Some(attributes)).await;
        println!("{:?}", alloc);
        Ok(assert!(alloc.is_err()))

    }


    #[async_std::test]
    async fn turn_realm_test() -> Result<(), StunTurnErrors> {
        sleep(Duration::from_secs(10));
        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();
        let peer : SocketAddr = PEER.parse().unwrap();  
        let mut ta = TurnClient {
            relayed_addrs : None,
            ftuple : FiveTuple{
                local : Some(local_addr),
                remote : Some(remote_addr),
                protocol : 17, 
            },
            auth : Username::new(String::from("username Pass")).unwrap(),
            expiry_time : Some(Duration::from_secs(100)), 
            permissions : None,
            data : "Hello peer test".as_bytes().to_vec(),
        };

        let mut attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
        attributes.push(S::Realm(Realm::new(String::from("wrong realm")).unwrap()));

        let alloc = allocate(ta, Some(peer), Some(attributes)).await;
        println!("{:?}", alloc);
        Ok(assert!(alloc.is_err()))
    }

    #[async_std::test]
    async fn turn_refresh_test() -> Result<(), StunTurnErrors> {
        sleep(Duration::from_secs(10));
        
        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();
        let peer : SocketAddr = PEER.parse().unwrap();
        let mut ta = TurnClient {
            relayed_addrs : None,
            ftuple : FiveTuple{
                local : Some(local_addr),
                remote : Some(remote_addr),
                protocol : 17, 
            },
            auth : Username::new(String::from("username Pass")).unwrap(), 
            expiry_time : Some(Duration::from_secs(100)),
            permissions : None, 
            data : "Hello peer test".as_bytes().to_vec(),
        };

        let mut attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
        attributes.push(S::Realm(Realm::new(String::from("realmtest")).unwrap()));

        let time = Instant::now();
        let alloc = allocate(ta.clone(), None, Some(attributes)).await?;
        let server_expiry_time = Duration::from_secs(10);
        Ok(assert!(Instant::now().duration_since(time) > server_expiry_time))
    }

    #[async_std::test]
    async fn turn_permission_test() -> Result<(), StunTurnErrors> {
        sleep(Duration::from_secs(10));
        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();
        let peer : SocketAddr = PEER.parse().unwrap();

        let mut ta = TurnClient {
            relayed_addrs : None,
            ftuple : FiveTuple{
                local : Some(local_addr),
                remote : Some(remote_addr),
                protocol : 17, 
            },
            auth : Username::new(String::from("username Pass")).unwrap(),
            expiry_time : Some(Duration::from_secs(100)),
            permissions : None, 
            data : "Hello peer test".as_bytes().to_vec(),
        };

        let mut attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
        attributes.push(S::Realm(Realm::new(String::from("realmtest")).unwrap()));

        let alloc = allocate(ta.clone(), None, Some(attributes)).await?;
        Ok(assert!(alloc.0.permissions.is_some()))
    }



    #[async_std::test]
    async fn stun_public_server_binding_test() -> Result<(), StunTurnErrors> {
        let addr = "stun1.l.google.com:19302".to_socket_addrs().await?.filter(|x|x.is_ipv4()).next().unwrap();

        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();

        let mut client = StunClient{
            timeout: 7,
            retry_interval: Duration::from_millis(500),
            socket: local_addr,
            software: Some("STUN Client"),
            attributes: None,
            password: Some("Pass"),
        };

        // These attributes are purely optional in this case.
        let attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
        client.attributes = Some(attributes);

        let actual = get_actual_address(client, addr).await?;
        println!("Actual address: {:?}", actual);
        let addr_string = actual.to_string();
        let vec : Vec<&str> = addr_string.split(":").collect();
        let ip = vec[0];
        assert_eq!(ip, ADDR);
        Ok(assert_eq!(ip, ADDR))
    }

    #[async_std::test]
    async fn stun_server_binding_test() -> Result<(), StunTurnErrors> {
        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();

        let mut client = StunClient{
            timeout: 7,
            retry_interval: Duration::from_millis(500),
            socket: local_addr,
            software: Some("STUN Client"),
            attributes: None,
            password: Some("Pass"),
        };

        let attributes = vec!(S::Username(Username::new(String::from("username Pass")).unwrap()));
        client.attributes = Some(attributes);

        let actual = get_actual_address(client, remote_addr).await?;
        println!("Actual address: {:?}", actual);
        let addr_string = actual.to_string();
        let vec : Vec<&str> = addr_string.split(":").collect();
        let ip = vec[0];
        Ok(assert_eq!(ip, ADDR))
    }

    #[async_std::test]
    async fn stun_error_message_test() -> Result<(), StunTurnErrors> {
        let remote_addr : SocketAddr = REMOTE_ADDR.parse().unwrap();
        let local_addr : SocketAddr = LOCAL_ADDR.parse().unwrap();

        let mut client = StunClient{
            timeout: 7,
            retry_interval: Duration::from_millis(500),
            socket: local_addr,
            software: Some("STUN Client"),
            attributes: None,
            password: Some("Pass"),
        };

        let mut attributes = vec!(S::ErrorCode(ErrorCode::new(400, String::from("Bad Request")).unwrap()));
        attributes.push(S::Username(Username::new(String::from("Test Pass")).unwrap())); 

        client.attributes = Some(attributes);

        let actual = get_actual_address(client, remote_addr).await;
        println!("{:?}", actual);
        Ok(assert!(actual.is_err()))


    }

   
}


/// An example of a TURN client. It returns the TurnClient passed in and a StunClient that it creates so that their contents can be checked by the tests.
pub async fn allocate(mut turn_alloc: TurnClient, peer : Option<SocketAddr>, mut attributes: Option<Vec<stun_codec::rfc5389::Attribute>>) -> Result<(TurnClient, StunClient), StunTurnErrors>{

    // Cloned the allocation for maniupulation in this function
    let mut cloned_alloc = TurnClient {
        relayed_addrs : turn_alloc.relayed_addrs.clone(),
        ftuple : turn_alloc.ftuple.clone(),
        auth : turn_alloc.auth.clone(),
        expiry_time : turn_alloc.expiry_time,
        permissions : turn_alloc.permissions.clone(),
        data : turn_alloc.data.clone(),
    };
   



    let local = UdpSocket::bind(cloned_alloc.ftuple.local.unwrap()).await?;
    
    let mut sc = StunClient {
        timeout: 7,
        retry_interval: Duration::from_millis(500),
        socket: cloned_alloc.ftuple.remote.unwrap(),
        software: Some("TURN Allocation"),
        attributes: None,
        password: Some("Pass"),
    };
    
    if attributes.is_some() {
        sc.attributes = Some(attributes.unwrap());
    }
    
    // Create and send binding
    let bind = sc.binding().unwrap();
    local.send_to(&bind, sc.socket).await?;
    
    let mut buf = [0; 256];

    let mut to_send = cloned_alloc.data.clone();
    let mut done = false;

    let mut lifetime = Instant::now(); 

    // Default addresses that will be overwritten
    let mut allocated_addr : SocketAddr = "0.0.0.0:0".parse().unwrap(); 
    let mut actual_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();

    // Set initial timeouts and deadlines
    use std::time::Instant;
    let time_limit = Duration::new(0, (sc.retry_interval.as_nanos() + (sc.retry_interval.as_nanos() * sc.timeout)) as u32);
    let deadline = Instant::now() + time_limit;
    let mut perm_deadline = Instant::now();
    let mut permission = false;
    loop {

        // Get new data to send to the client if all previous data has been sent
        if cloned_alloc.data.clone().is_empty() {
            let new_data = get_data().await?;
            if new_data.is_some() {
                println!("new_data {:?}", new_data);
                cloned_alloc.data = new_data.unwrap(); 
            } else {
                done = true;
            } 
        }

        let mut len : usize = 0;
        let mut addr : SocketAddr = "0.0.0.0:0".parse().unwrap();

        // Wait to receive data but retry loop after 10 seconds
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
            Err(e) => Err(e)?,
        }

        let instant = Instant::now();
        lifetime = instant + cloned_alloc.expiry_time.unwrap();
        println!("Allocated address: {:?}", allocated_addr);

        // Request new permission if current one is about to expire
        if Instant::now().duration_since(perm_deadline) > Duration::from_secs(250) {
            println!("Requesting updated permission");
            cloned_alloc.request_permission(allocated_addr, &local).await?;
            permission = true;
            perm_deadline = Instant::now();
            continue
        }
        
        // Request a new lifetime if current is near expiring
        if lifetime.duration_since(instant) < cloned_alloc.expiry_time.unwrap().sub(Duration::from_secs(20)) {
            println!("Refreshing lifetime");
            cloned_alloc.refresh(Duration::from_secs(100), allocated_addr, &local).await?;
        }

        if len == 0 {
            continue
        }

        let buf = &buf[0..len];

        // Don't use data from the wrong address
        if addr != sc.socket {
            println!("problem with addresses {:?} {:?}", addr, sc.socket);
            continue;
        }

        let decoded = cloned_alloc.decode(buf).await?.unwrap();

        // Get the allocated address
        if decoded.0.is_some() {

            // comment out this loop for slower, possibly broken, sending all the time
            if decoded.0.unwrap().to_string() != "0.0.0.0:0" {
                allocated_addr = decoded.0.unwrap();
                let mut test_allocated_addr = cloned_alloc.ftuple.remote.unwrap();
                test_allocated_addr.set_port(allocated_addr.port());
                allocated_addr = test_allocated_addr;
                sc.socket = test_allocated_addr;
            } 
        } 
        // Get the server reflexive address
        if decoded.1.is_some() {
            actual_addr = decoded.1.unwrap();
        }
        // Get negotiated lifetime 
        if decoded.2.is_some() {
            lifetime = Instant::now() + decoded.2.unwrap();
            cloned_alloc.expiry_time = Some(decoded.2.unwrap());
        }
        // Get channels NOT IMPLEMENTED
        if decoded.3.is_some() {
            let channels = decoded.3.unwrap();
        }
        // Get and add or updated a new permission
        if decoded.5.is_some() {
            if cloned_alloc.permissions.is_none() {
                println!("Creating a new permission");
                let permission = Some(vec!((sc.socket, Instant::now())));
                cloned_alloc.permissions = permission;
            } else {
                let mut unwrapped = turn_alloc.permissions.clone().unwrap();
                unwrapped.push((sc.socket, Instant::now()));
                cloned_alloc.permissions = Some(unwrapped);
            }
            perm_deadline = Instant::now();
        }

        println!("Allocated address: {:?}", sc.socket);
        println!("Server Reflexive Address: {:?}",actual_addr);
        println!("Negotiated lifetime value: {:?}", lifetime);
        
        // Repeat loop if address hasn't been updated
        if allocated_addr.to_string() == "0.0.0.0:0" {
            continue;
        }

        // Request a permission after an allocation has been made
        if !permission {
            cloned_alloc.request_permission(allocated_addr, &local).await?;
            permission = true;
            perm_deadline = Instant::now();
        }


        let lifetime_check = Duration::from_secs(10);        // Sometimes this not entered. Need to check over the lifetimes as well.
        if lifetime.duration_since(instant) < cloned_alloc.expiry_time.unwrap().sub(lifetime_check) && decoded.2.is_some(){
            cloned_alloc.refresh(Duration::from_secs(100), allocated_addr, &local).await?;
        }
    

        println!("Sending the data");
        // Send the data and peer to the allocation
        if peer.is_some() {
            cloned_alloc.send_data(peer.unwrap(), to_send.clone(), allocated_addr, &local).await?;
        }
        to_send = Vec::new();
        cloned_alloc.data = to_send.clone();

        // self.receive_data();
        if Instant::now().duration_since(perm_deadline) > Duration::from_secs(300) {
            return Err(StunTurnErrors::PermissionTimedOut)
        }

        // Signal the allocation that it isn't needed any more and close the client
        if done {
            cloned_alloc.refresh(Duration::from_secs(0), allocated_addr, &local).await?;
            return Ok((cloned_alloc.clone(), sc));
        }
        continue
    }   
}

/// An example of a STUN client
pub async fn get_actual_address(mut stun_client: StunClient, remote_address: SocketAddr) -> Result<SocketAddr, StunTurnErrors>{
    
    let remote = StunClient{
        timeout: stun_client.timeout,
        retry_interval: stun_client.retry_interval,
        socket: remote_address,
        software: Some("STUN Client"),
        attributes: stun_client.attributes.clone(),
        password: stun_client.password,
    };

    
    let addr = stun_client.socket;
    let local = UdpSocket::bind(addr).await?;

    // Create a binding and send to the server
    let bind = remote.binding().unwrap();
    local.send_to(&bind, remote.socket).await?;

    let mut buf = [0; 256];

    let mut previous_timeout = None;

    let time_limit = Duration::new(0, (remote.retry_interval.as_nanos() + (remote.retry_interval.as_nanos() * remote.timeout)) as u32);
    let deadline = Instant::now() + time_limit;
    loop {
        let now = Instant::now();
        if now >= deadline {
            Err(format!("Timed out waiting for STUN server reply"))?;
        }
        let mt = remote.retry_interval.min(deadline - now);
        if Some(mt) != previous_timeout {
            previous_timeout = Some(mt);
        }
        
        // Wait for the server to respond and resend if there is a timeout
        let (len, addr) = match local.recv_from(&mut buf[..]).await {
            Ok(x) => x,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {
                local.send_to(&bind, remote.socket).await?;
                continue;
            },
            Err(e) => Err(e)?,
        };

        let buf = &buf[0..len];
        
        // Don't accept data from the wrong address
        if addr != remote.socket {
            continue;
        }

        // Get the address to return
        let external_addr = remote.decode_address(buf)?;
        if external_addr.is_some() {
            return Ok(external_addr.unwrap())
        }
        
    }
    
}

/// A helper function to gather data from a user that can be sent in the TURN implementation.
pub async fn get_data() -> Result<Option<Vec<u8>>, StunTurnErrors> {
    let mut buf = [0; 1024];
    match io::stdin().read(&mut buf).await {
        // If empty line entered then finish reading.
        Ok(1) => return Ok(None),
        Ok(size) => {
            let data = buf[..size].to_vec();
            return Ok(Some(data))
        },
        Err(_e) => return Ok(None)
    }
}
