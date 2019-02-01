#![allow(unused)]

extern crate tokio;
extern crate turnclient;


use std::net::{SocketAddr};

use tokio::net::udp::UdpSocket;
use tokio::prelude::{Future,Stream};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args : Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: proxy turn_host:port username password < interactive commands");
        Err(format!("Invalid command-line arguments"))?;
    }

    let turn_server : SocketAddr = args[1].parse()?;
    let username : String = args[2].parse()?;
    let password : String = args[3].parse()?;

    let local_addr : SocketAddr = "0.0.0.0:0".parse().unwrap();
    let udp = tokio::net::udp::UdpSocket::bind(&local_addr)?;

    let c = turnclient::TurnClientBuilder::new(turn_server, username, password);
    let f = c.allocate(udp)
    .and_then(|turnclient| {
        turnclient.for_each(|_| {
            futures::future::ok(())
        })
    })
    .map_err(|e|eprintln!("{}", e))
    ;

    tokio::runtime::current_thread::run(f);

    Ok(())
}
