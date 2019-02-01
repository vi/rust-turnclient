#![allow(unused)]

extern crate bytecodec;
extern crate stun_codec;
extern crate rand;

extern crate futures;
extern crate tokio_udp;
extern crate tokio_timer;

use stun_codec::{MessageDecoder, MessageEncoder};

use bytecodec::{DecodeExt, EncodeExt};
use std::net::{SocketAddr};
use stun_codec::rfc5389::attributes::{
     Software,
     XorMappedAddress,
     // XorMappedAddress2, 
     MappedAddress,
};
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, TransactionId};
use std::time::Duration;

use futures::{Stream, Sink, Future};

/// Primitive error handling used in this library.
/// File an issue if you don't like it.
pub type Error = Box<dyn std::error::Error>;

use tokio_udp::UdpSocket;



/// Options for connecting to TURN server
pub struct TurnClientBuilder {
    /// Address of the TURN server
    pub turn_server: SocketAddr,
    /// Username for TURN authentication
    pub username: String,
    /// Password for TURN authentication
    pub password: String,

    /// "End-to-end" timeout for the initial allocation operation.
    pub alloc_timeout: Duration,
    /// How often to repeat varions requests
    pub retry_interval: Duration,
    /// How often to renew the allocation
    pub refresh_interval: Duration,
    /// `SOFTWARE` attribute value in requests
    /// None means no attribute
    pub software: Option<&'static str>,
}

impl TurnClientBuilder {
    /// A constructor with obligatory parameters
    pub fn new(turn_server: SocketAddr, username: String, password: String) -> Self {
        TurnClientBuilder {
            turn_server,
            username,
            password,
            alloc_timeout: Duration::from_secs(15),
            retry_interval: Duration::from_secs(1),
            refresh_interval: Duration::from_secs(60),
            software: Some("SimpleRustTurnClient"),
        }
    }

    // too lazy to bring in builder pattern methods now

    pub fn allocate() -> impl Future<Item=TurnClient, Error=Error> {
        futures::future::result(unimplemented!())
    }
}

pub struct TurnClient {
    opts: TurnClientBuilder,
    udp: UdpSocket,
}

impl TurnClient {
    /// Consume this TURN client, returning back control of used UDP socket
    pub fn into_udp_socket(self) -> UdpSocket {
        self.udp
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
