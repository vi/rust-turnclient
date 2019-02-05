extern crate tokio;
extern crate turnclient;
extern crate futuristic;
extern crate either;


use std::net::{SocketAddr};

use tokio::net::udp::{UdpSocket,UdpFramed};
use tokio::prelude::{Future,Stream,Sink};

use futuristic::SinkTools;
use either::Either;

use turnclient::{ChannelUsage,MessageFromTurnServer,MessageToTurnServer};

enum FromForwardOrFromTurn {
    FromTurn(MessageFromTurnServer),
    FromForward(Vec<u8>),
}

enum ToForwardOrToTurn {
    ToTurn(MessageToTurnServer),
    ToForward(Vec<u8>),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args : Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!("Usage: proxy turn_host:port username password peer_host:port script_to_run_when_allocation_is_ready forward_ip:port");
        eprintln!("This program connectes to a TURN server, authorizes specified peer adress at TURN server, then runs specified program with TURN-allocated proxy host:port, then forwards everything from it to forward_ip:port");
        eprintln!("Example: proxy 188.166.127.102:3478 someuser somepassword /bin/echo 127.0.0.1:1194");
        Err(format!("Invalid command-line arguments"))?;
    }

    let turn_server : SocketAddr = args[1].parse()?;
    let username : String = args[2].parse()?;
    let password : String = args[3].parse()?;
    let peer_addr : SocketAddr = args[4].parse()?;
    let script: String = args[5].parse()?;
    let forward_addr: SocketAddr = args[6].parse()?;

    let local_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();
    let udp = UdpSocket::bind(&local_addr)?; // for TURN
    let udp2 = UdpSocket::bind(&local_addr)?; // for forward_addr

    let c = turnclient::TurnClientBuilder::new(turn_server, username, password);
    let (turnsink, turnstream) = c.build_and_send_request(udp).split();

    let udpf = UdpFramed::new(udp2, tokio::codec::BytesCodec::new());

    let (forwsink, forwstream) = udpf.split();

    let str1 = forwstream.map(|(buf,_addr)| {
        FromForwardOrFromTurn::FromForward(buf[..].to_vec())
    }).map_err(|e|e.into());
    let str2 = turnstream.map(|x| {
        FromForwardOrFromTurn::FromTurn(x)
    });
    let str_ = str1.select(str2);

    let sin = turnsink.fork(forwsink.sink_map_err(|e|e.into()),move |x| {
        match x {
            ToForwardOrToTurn::ToTurn(x) => Either::Left(x),
            ToForwardOrToTurn::ToForward(x) => Either::Right((x.into(), forward_addr)),
        }
    });

    use MessageFromTurnServer::*;
    use ToForwardOrToTurn::*;
    use FromForwardOrFromTurn::*;
    use MessageToTurnServer::*;

    let f = str_.map(move |x| {
            match x {
                FromTurn(AllocationGranted{relay_address,..}) => {
                    //eprintln!("{:?}", relay_address);
                    let ra = match relay_address {
                        SocketAddr::V4(x) => format!("{}", x),
                        _ => format!("?"),
                    };
                    let _ = std::process::Command::new(script.clone()).arg(ra).status();
                    ToTurn(AddPermission(peer_addr, ChannelUsage::WithChannel))
                },
                FromTurn(RecvFrom(_sa,data)) => {
                    //eprintln!(">");
                    ToForward(data)
                },
                FromForward(data) => {
                    //eprintln!("<");
                    ToTurn(SendTo(peer_addr, data))
                }
                _ => ToTurn(MessageToTurnServer::Noop),
            }
        }).forward(sin)
        .and_then(|(_,_)|{
            futures::future::ok(())
        })
        .map_err(|e|eprintln!("{}", e));

    tokio::runtime::current_thread::run(f);

    Ok(())
}
