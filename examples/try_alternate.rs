// Not an actual example, just a code for other one-off experiment
extern crate bytecodec;
extern crate stun_codec;

use std::net::{UdpSocket,SocketAddr};

use stun_codec::{rfc5389::Attribute,Message};
use bytecodec::DecodeExt;
use bytecodec::EncodeExt;
use stun_codec::{MessageDecoder, MessageEncoder, MessageClass};

use stun_codec::rfc5389::attributes::{
     Software,
     ErrorCode,
     AlternateServer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args : Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("This is a very simple STUN/TURN \"server\" that always serves '300 Try Alternate' reply, redirecting clients to the specified actual STUN/TURN server.");
        eprintln!("Usage: try_alternate listen_UDP_host:port redirect_TURN_host:port");
        eprintln!("Example: try_alternate 0.0.0.0:3478 104.131.203.210:3478");
        Err(format!("Invalid command-line arguments"))?;
    }

    let local_addr : SocketAddr = args[1].parse().unwrap();
    let redirect_addr : SocketAddr = args[2].parse().unwrap();
    let udp = UdpSocket::bind(local_addr).unwrap();

    let mut buf = [0;512];

    loop {
        if let Err(e) = (||{
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
                "try_alternate".to_owned(),
            )?));

            message.add_attribute(Attribute::ErrorCode(ErrorCode::new(
                stun_codec::rfc5389::errors::TryAlternate::CODEPOINT, 
                "Try Alternate".to_string(),
            )?));

            message.add_attribute(Attribute::AlternateServer(AlternateServer::new(
                redirect_addr,
            )));
            

            // Encodes the message
            let mut encoder = MessageEncoder::new();
            let bytes = encoder.encode_into_bytes(message.clone())?;

            udp.send_to(&bytes[..], addr)?;
            Ok(())
        })() {
            let e : Box<dyn std::error::Error> = e;
            eprintln!("{}", e);
        }
    }
}
