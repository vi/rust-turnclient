extern crate tokio;
extern crate turnclient;


use std::net::{SocketAddr};

use futures::{StreamExt};

use turnclient::{ChannelUsage,MessageFromTurnServer,MessageToTurnServer};

#[tokio::main(flavor="current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args : Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: echo turn_host:port username password peer_host:port");
        Err(format!("Invalid command-line arguments"))?;
    }

    let turn_server : SocketAddr = args[1].parse()?;
    let username : String = args[2].parse()?;
    let password : String = args[3].parse()?;
    let peer_addr : SocketAddr = args[4].parse()?;

    let local_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();
    let udp = tokio::net::UdpSocket::bind(&local_addr).await?;

    let c = turnclient::TurnClientBuilder::new(turn_server, username, password);
    let (turnsink, turnstream) = c.build_and_send_request(udp).split();
    let f = turnstream.map(move |x| {
            //println!("{:?}", x);
            print!(".");
            Ok(match x {
                Ok(MessageFromTurnServer::AllocationGranted{..}) => {
                    println!("Allocation granted: {:?}", x);
                    MessageToTurnServer::AddPermission(peer_addr, ChannelUsage::WithChannel)
                },
                Ok(MessageFromTurnServer::RecvFrom(sa,data)) => {
                    println!("Incoming {} bytes from {}", data.len(), sa);
                    MessageToTurnServer::SendTo(sa, data)
                    //turnclient::MessageToTurnServer::Disconnect
                },
                Err(e) => {
                    eprintln!("{}", e);
                    MessageToTurnServer::Noop
                }
                _ => MessageToTurnServer::Noop,
            })
        }).forward(turnsink);

    if let Err(e) = f.await {
        eprintln!("{}", e);
    }

    Ok(())
}
