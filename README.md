Simple Rust TURN client for UDP - traverse even strict NAT; async only currently

Cleaned-up example snippet:

```rust
let udp : tokio::net::udp::UdpSocket; 
let c = turnclient::TurnClientBuilder::new(turn_server, username, password);
let (turnsink, turnstream) = c.build_and_send_request(udp).split();
turnstream.map(move |event| {
    match event {
        MessageFromTurnServer::AllocationGranted{ relay_address, ..} => {
            MessageToTurnServer::AddPermission(peer_addr, ChannelUsage::WithChannel)
        },
        MessageFromTurnServer::RecvFrom(sa,data) => {
            MessageToTurnServer::SendTo(sa, data)
        },
        _ => MessageToTurnServer::Noop,
    }
}).forward(turnsink); // run this with Tokio
```

See crate-level docs for further instructions.

Not implemented / TODO / cons:

* Removing permissions. They keep on getting refreshed until you close the entire allocation.
* Quadratical complexity, linear number of UDP datagrams in case of N actibe permissions.
* TCP or TLS transport.
* Using short-term credentials instead of long-term.
* "Don't fragment" specifier on sent datagrams
* Even/odd port allocation
* Error handling is ad-hoc `Box<dyn std::error::Error>`, with just a text strings.
* Message-integrity is not checked for server replies.
* Allocation-heavy, uses Vec<u8> for byte buffers.

Examples:

* `echo.rs` - Connect to specified TURN server, authorize specified peer and act as an echo server for it (snippet depicted above)
