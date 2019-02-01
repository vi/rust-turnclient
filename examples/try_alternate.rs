// Not an actual example, just a code for other one-off experiment
#![allow(unused)]

extern crate bytecodec;
extern crate stun_codec;

use std::net::{UdpSocket,SocketAddr};

use stun_codec::{rfc5389::Attribute,Message};
use bytecodec::DecodeExt;
use bytecodec::EncodeExt;
use stun_codec::{MessageDecoder, MessageEncoder, MessageClass};
use stun_codec::rfc5389::methods::BINDING;

use stun_codec::rfc5389::attributes::{
     Software,
     ErrorCode,
     AlternateServer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local_addr : SocketAddr = "0.0.0.0:3478".parse().unwrap();
    let udp = UdpSocket::bind(local_addr).unwrap();

    let mut buf = [0;512];

    loop {
        let (len, addr) = udp.recv_from(&mut buf[..])?;
        let buf = &buf[0..len];

        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded : Message<Attribute> = decoder
            .decode_from_bytes(buf)?
            .map_err(|_| format!("Broken STUN reply"))?;


        let mut message = Message::new(
            MessageClass::ErrorResponse,
            decoded.method(),
            decoded.transaction_id(),
        );
        
        message.add_attribute(Attribute::Software(Software::new(
            "AlternateServerReplier".to_owned(),
        )?));

        message.add_attribute(Attribute::ErrorCode(ErrorCode::new(
            stun_codec::rfc5389::errors::TryAlternate::CODEPOINT, 
            "Try Alternate".to_string(),
        )?));

        message.add_attribute(Attribute::AlternateServer(AlternateServer::new(
            "104.131.203.210:3478".parse().unwrap(),
        )));
        

        // Encodes the message
        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message.clone())?;

        udp.send_to(&bytes[..], addr)?;

    }
}
