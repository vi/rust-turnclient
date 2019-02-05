#![deny(missing_docs)]

//! Simple async TURN client.
//! 
//! Usage:
//! 
//! 1. Create `TurnClientBuilder`
//! 2. `build_and_send_request`
//! 3. `split` the resulting thing to `Stream` and `Sink`
//! 4. Wait for `AllocationGranted` event from Stream
//! 5. Create permission or channel with `AddPermission` message
//! 6. Send datagrams to the peer with a `SendTo` message to `TurnClient`'s `Sink` interface, receive datagrams from the peer by handling `RecvFrom` message from `TurnClient`'s `Stream` interface.
//! 
//! You may want to build a `stream -> map -> sink` chain using `Stream::forward` or `Sink::send_all`.
//! 
//! You need to handle errors from `Stream::poll`, otherwise somebody can DoS your client by sending tricky packets.
//! 
//! Not implemented / TODO / cons:
//! 
//! * Removing permissions. They keep on getting refreshed until you close the entire allocation.
//! * Quadratical complexity, linear number of UDP datagrams in case of N actibe permissions.
//! * TCP or TLS transport.
//! * Using short-term credentials instead of long-term.
//! * "Don't fragment" specifier on sent datagrams
//! * Even/odd port allocation
//! * Error handling is ad-hoc `Box<dyn std::error::Error>`, with just a text strings.
//! * Message-integrity is not checked for server replies.
//! * Allocation-heavy, uses `Vec<u8>` for byte buffers.
//! 
//! Examples:
//! 
//! * `echo.rs` - Connect to specified TURN server, authorize specified peer and act as an echo server for it.

const PERM_REFRESH_INTERVAL : u64 = 180;

extern crate bytecodec;
#[macro_use]
extern crate stun_codec;
#[macro_use]
extern crate trackable;
extern crate rand;

extern crate futures;
extern crate tokio_udp;
extern crate tokio_timer;

extern crate fnv;

#[macro_use]
extern crate slab_typesafe;

use stun_codec::{MessageDecoder, MessageEncoder};

use bytecodec::{DecodeExt, EncodeExt};
use std::net::{SocketAddr};
use stun_codec::rfc5389::attributes::{
    Software,
    Realm,
    Nonce,
    ErrorCode,
    MessageIntegrity,
    Username,
    XorMappedAddress,
    AlternateServer,
};
use stun_codec::rfc5766::attributes::{
    RequestedTransport,
    XorRelayAddress,
    XorPeerAddress,
    Lifetime,
    Data,
    ChannelNumber,
};
//use stun_codec::rfc5389::{Attribute as StunAttribute};
//use stun_codec::rfc5766::{Attribute as TurnAttribute};
use stun_codec::rfc5766::methods::{
    ALLOCATE,
    REFRESH,
    CREATE_PERMISSION,
    CHANNEL_BIND,
    SEND,
};
use stun_codec::{Message, MessageClass, TransactionId};
use std::time::{Instant,Duration};
use self::attrs::Attribute;

use futures::{Stream, Sink, Future, Poll, Async, StartSend, AsyncSink};

use fnv::FnvHashMap as HashMap;

mod attrs { 
    extern crate stun_codec;
    // Taken from rusturn/src/attribute.rs
    use stun_codec::rfc5389::attributes::*;
    use stun_codec::rfc5766::attributes::*;

    define_attribute_enums!(
        Attribute,
        AttributeDecoder,
        AttributeEncoder,
        [
            // RFC 5389
            MappedAddress,
            Username,
            MessageIntegrity,
            ErrorCode,
            UnknownAttributes,
            Realm,
            Nonce,
            XorMappedAddress,
            Software,
            AlternateServer,
            Fingerprint,
            // RFC 5766
            ChannelNumber,
            Lifetime,
            XorPeerAddress,
            Data,
            XorRelayAddress,
            EvenPort,
            RequestedTransport,
            DontFragment,
            ReservationToken
        ]
    );

}

/// Primitive error handling used in this library.
/// File an issue if you don't like it.
pub type Error = Box<dyn std::error::Error>;

use tokio_udp::UdpSocket;

use tokio_timer::{Interval,Delay};

use slab_typesafe::Slab;



/// Options for connecting to TURN server
pub struct TurnClientBuilder {
    /// Address of the TURN server
    pub turn_server: SocketAddr,
    /// Username for TURN authentication
    pub username: String,
    /// Password for TURN authentication
    pub password: String,

    /// Maximum number of retries for any request
    pub max_retries: usize,
    /// How often to retry varions requests
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
            max_retries: 10,
            retry_interval: Duration::from_secs(1),
            refresh_interval: Duration::from_secs(30),
            software: Some("SimpleRustTurnClient"),
        }
    }

    // too lazy to bring in builder pattern methods now

    /// Finish setting options and get object to be polled.
    /// Does not actually send the allocate request until returned `TurnClient` is polled.
    pub fn build_and_send_request(self, udp: UdpSocket) -> TurnClient {
        let mut tc = TurnClient{
            opts: self,
            udp,

            inflight: HashMap::with_capacity_and_hasher(2, Default::default()),

            when_to_renew_the_allocation: None,
            realm: None,
            nonce: None,

            permissions: Slab::with_capacity(1),
            sockaddr2perm: HashMap::with_capacity_and_hasher(1, Default::default()),

            permissions_pinger: None,
            shutdown: false,
        };
        tc.send_allocate_request(false).unwrap();
        tc
    }
}

/// Callbacks from `TurnServer`
#[derive(Debug)]
pub enum MessageFromTurnServer {
    /// Setup is finished. Don't send AddPermission until this event arrives.
    AllocationGranted {
        /// Address and port that is allocated for us by the TURN server.
        /// Permitted hosts may send to it and we'll receive `RecvFrom` message.
        relay_address: SocketAddr,
        /// External IP address and port of UDP socket used to contact TURN server.
        /// Probably useless, unless you also want to try direct, non-TURN NAT traversal.
        mapped_address: SocketAddr,
        /// SERVER attribute returned by TURN server, if any.
        server_software: Option<String>,
    },

    /// Server is busy and requesting us to use alternative server.
    /// The stream would end after this message.
    RedirectedToAlternateServer(SocketAddr),

    /// Permission that you have requested by writing to sink has been successfully created.
    PermissionCreated(SocketAddr),

    /// Incoming datagram from peer, regardless whether it comes from ChannelData or Indication.
    RecvFrom(SocketAddr, Vec<u8>),

    /// Reaction to the `Disconnect` message, received response with zero lifetime.
    /// The stream would end after this message.
    Disconnected,

    /// This variant can be safely ignored.
    /// Each incoming packet from TURN server corresponds to some message here, you may
    /// use this variant as a kind of watchdog that TURN server is operating normally
    /// Expect this arrive each minute or so.
    APacketIsReceivedAndAutomaticallyHandled,

    /// A packet from wrong address or an unexpected STUN/TURN message or just malformed
    ForeignPacket(SocketAddr, Vec<u8>),
}

enum InflightRequestStatus {
    SendNow,
    RetryLater(Delay),
    TimedOut,
}

/// Whether to just create permission of also allocate a channel for it.
/// I don't see much reasons not to allocate a channel.
#[derive(Debug,PartialEq,Eq,Ord,PartialOrd,Hash)]
pub enum ChannelUsage {
    /// Create a channel, resulting in shorter datagrams between you and TURN for this peer.
    WithChannel,
    /// Only create permission and use send indications (more overhead compared to channel messages)
    JustPermission,
}

/// Requests and indications to be sent to TURN server
#[derive(Debug)]
pub enum MessageToTurnServer {
    /// Ignored
    Noop,

    /// Grant access for this SocketAddr (external UDP ip:port) to send us datagrams
    /// (and for us to send datagrams to it)
    AddPermission(SocketAddr, ChannelUsage),

    /// Send this datagram to this peer
    SendTo(SocketAddr, Vec<u8>),

    /// Expire the allocation and stop emitting new requests
    Disconnect,
}

type CompletionHook = Box<FnMut(&mut TurnClient)->Result<Option<MessageFromTurnServer>,Error>>;

/// Unaccepted request being retried
struct InflightRequest {
    status: InflightRequestStatus,
    data: Vec<u8>,
    retryctr: usize,
    completion_hook: Option<CompletionHook>,
}

declare_slab_token!(PermissionHandle);

impl PermissionHandle {
    pub fn as_channel_number(&self) -> Option<u16> {
        if self.0 <= 0x3FFE {
            Some(0x4000 + (self.0 as u16))
        } else {
            None
        }
    }

    pub fn from_channel_number(n: u16) -> Option<Self> {
        if n >= 0x4000 && n <= 0x7FFE {
            Some(((n as usize) - 0x4000).into())
        } else {
            None
        }
    }
}

/// Association between TURN client and it's peer
struct Permission {
    addr : SocketAddr,
    channelized: bool,
    creation_already_reported: bool,
}

/// The thing to be `split` to `Stream<Item=MessageFromTurnServer>` and `Sink<Item=MessageToTurnServer>`.
/// Look at crate-level doc for more details.
pub struct TurnClient {
    opts: TurnClientBuilder,
    udp: UdpSocket,

    inflight: HashMap<TransactionId, InflightRequest>,

    /// None means not yet allocated
    when_to_renew_the_allocation: Option<Delay>,

    realm: Option<Realm>,
    nonce: Option<Nonce>,

    permissions: Slab<PermissionHandle, Permission>,
    sockaddr2perm: HashMap<SocketAddr, PermissionHandle>,

    permissions_pinger: Option<Interval>,
    shutdown: bool,
}

/// Simple TURN client in form of `Stream<Item=MessageFromTurnServer>` and `Sink<SinkItem=MessageToTurnServer>`.
/// 
/// Stream side should be continually polled, or the client expires.
/// Requests are actually sent by `Stream`'s poll.
/// 
/// Use `Stream::split`.
impl TurnClient {
    /// Consume this TURN client, returning back control of used UDP socket
    /// Does not expire the allocation, so expect datagrams to keep on coming from
    /// TURN server
    pub fn into_udp_socket(self) -> UdpSocket {
        self.udp
    }
}

fn gen_transaction_id() -> TransactionId {
    use rand::Rng;
    let random_bytes = rand::thread_rng().gen::<[u8; 12]>();
    TransactionId::new(random_bytes)
}

impl TurnClient {
    /// Send allocate or refresh request
    fn send_allocate_request(&mut self, shutdown: bool) -> Result<(), Error> {
        let transid = gen_transaction_id();

        let method = if self.when_to_renew_the_allocation.is_none() {
            ALLOCATE
        } else {
            REFRESH
        };
        let mut message : Message<Attribute> = Message::new(MessageClass::Request, method, transid);
              
        if let Some(s) = self.opts.software {
            message.add_attribute(Attribute::Software(Software::new(
                s.to_owned(),
            )?));
        }
        
        if method == ALLOCATE {
            message.add_attribute(Attribute::RequestedTransport(
                RequestedTransport::new(17 /* UDP */)
            ));
        }

        if shutdown {
            message.add_attribute(Attribute::Lifetime(
                Lifetime::new(Duration::from_secs(0))?
            ));
        }
        
        self.sign_request(&mut message)?;
        self.file_request(transid, message, None)?;
    
        Ok(())
    }

    fn process_alloc_lifetime(&self, mut lt: Duration) -> Duration {
        if lt < Duration::from_secs(90) {
            lt = Duration::from_secs(5);
        } else {
            lt = lt - Duration::from_secs(60);
        }
        if lt > self.opts.refresh_interval {
            lt = self.opts.refresh_interval;
        }
        lt
    }

    fn sign_request(&self, message: &mut Message<Attribute>) -> Result<(),Error> {
        let username = Username::new(self.opts.username.clone())?;
        message.add_attribute(Attribute::Username(
            username.clone()
        ));

        if let (Some(re), Some(no)) = (self.realm.clone(), self.nonce.clone()) {
            message.add_attribute(Attribute::Realm(re.clone()));
            message.add_attribute(Attribute::Nonce(no));
        
            message.add_attribute(Attribute::MessageIntegrity(
                MessageIntegrity::new_long_term_credential(
                        &message, 
                        &username,
                        &re,
                        self.opts.password.as_str())?
            ));
        }
        Ok(())
    }

    fn file_request(
                &mut self, 
                transid: TransactionId,
                message: Message<Attribute>,
                completion_hook: Option<CompletionHook>,
    ) -> Result<(),Error> {
        if self.shutdown {
            return Ok(())
        }
        // Encodes the message
        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;

        let rq = InflightRequest {
            status: InflightRequestStatus::SendNow,
            data: bytes,
            retryctr: 0,
            completion_hook,
        };
        self.inflight.insert(transid, rq);

        Ok(())
    }
    // TODO: multiple addresses per request
    fn send_perm_request(&mut self, h: PermissionHandle) -> Result<(), Error> {
        let p = &self.permissions[h];

        
        let transid = gen_transaction_id();

        let method = if p.channelized {
            CHANNEL_BIND
        } else {
            CREATE_PERMISSION
        };
        let mut message : Message<Attribute> = Message::new(MessageClass::Request, method, transid);
              
        if let Some(s) = self.opts.software {
            message.add_attribute(Attribute::Software(Software::new(
                s.to_owned(),
            )?));
        }

        message.add_attribute(Attribute::XorPeerAddress(
            XorPeerAddress::new(p.addr)
        ));

        if p.channelized {
            let chn = h.as_channel_number().ok_or("Channel number overflow")?;
            message.add_attribute(Attribute::ChannelNumber(
                ChannelNumber::new(chn)?
            ));
        }

        let hook : CompletionHook = Box::new(move |_self|{
            let p = &mut _self.permissions[h];
            let msg = if p.creation_already_reported {
                MessageFromTurnServer::APacketIsReceivedAndAutomaticallyHandled
            } else {
                p.creation_already_reported = true;
                MessageFromTurnServer::PermissionCreated(p.addr)
            };
            Ok(Some(msg))
        });

        self.sign_request(&mut message)?;
        self.file_request(transid, message, Some(hook))?;
    
        Ok(())
    }
    
    fn send_data_indication(&mut self, sa: SocketAddr, data: Vec<u8>) -> Result<(),Error> {
        
        if let Some(p) = self.sockaddr2perm.get(&sa) {
            if let Some(cn) = p.as_channel_number() {
                let mut b = Vec::with_capacity(data.len() + 4);
                let l = data.len();
                b.push( ((cn & 0xFF00) >> 8) as u8);
                b.push( ((cn & 0x00FF) >> 0) as u8);
                b.push( ((l  & 0xFF00) >> 8) as u8);
                b.push( ((l  & 0x00FF) >> 0) as u8);
                b.extend_from_slice(&data[..]);

                match self.udp.poll_send_to(&b[..], &self.opts.turn_server) {
                    Err(e)=>Err(e)?,
                    Ok(Async::NotReady) => Err("UDP socket became not write-ready after reporting readiness")?,
                    Ok(Async::Ready(len)) => {
                        assert_eq!(len, l+4)
                    }
                }
                return Ok(())
            }
        }

        let transid = gen_transaction_id();

        let method = SEND;
        let mut message : Message<Attribute> = Message::new(MessageClass::Indication, method, transid);
          
        message.add_attribute(Attribute::XorPeerAddress(
            XorPeerAddress::new(sa)
        ));
        message.add_attribute(Attribute::Data(
            Data::new(data)?
        ));
        
        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;

        match self.udp.poll_send_to(&bytes[..], &self.opts.turn_server) {
            Err(e)=>Err(e)?,
            Ok(Async::NotReady) => Err("UDP socket became not write-ready after reporting readiness")?,
            Ok(Async::Ready(len)) => {
                assert_eq!(len, bytes.len())
            }
        }
        
        Ok(())
    }

    /// Handle incoming packet from TURN server
    fn handle_incoming_packet(&mut self, buf:&[u8]) -> Result<MessageFromTurnServer, Error> {
        use self::MessageFromTurnServer::*;
        use stun_codec::MessageClass::{SuccessResponse, ErrorResponse, Indication, Request};

        let mut foreign_packet = false;

        // Handle incoming ChannelData:
        if buf.len() < 4 {
            foreign_packet = true;
        } else {
            if buf[0] >= 0x40 && buf[0] <= 0x7F {
                let chnum = (buf[0] as u16)<<8  |  (buf[1] as u16);
                let len = (buf[2] as u16) << 8 | (buf[3] as u16);

                let h = PermissionHandle::from_channel_number(chnum);

                if h.is_none() || buf.len() < (len as usize)+4 {
                    foreign_packet = true;
                } else {
                    if let Some(p) = self.permissions.get(h.unwrap()) {
                        return Ok(MessageFromTurnServer::RecvFrom(
                            p.addr,
                            buf[4..].to_vec(),
                        ))
                    } else {
                        foreign_packet = true;
                    } 
                }
            }
        }

        // Handle everything else:

        if buf.len() < 18 {
            foreign_packet = true;
        }

        if foreign_packet {
            return Ok(ForeignPacket(self.opts.turn_server, buf.to_vec()));
        }

        let mut decoder = MessageDecoder::<Attribute>::new();

        let decoded = decoder
            .decode_from_bytes(buf)?
            .map_err(|_| format!("Broken TURN reply"))?;

        let tid = decoded.transaction_id();

        if decoded.class() == Indication {
            let pa = decoded.get_attribute::<XorPeerAddress>().ok_or("No XorPeerAddress in data indication")?;
            let data = decoded.get_attribute::<Data>().ok_or("No Data attribute in indication")?;

            return Ok(MessageFromTurnServer::RecvFrom(
                pa.address(),
                data.data().to_vec(),
            ));
        }

        if self.inflight.get(&tid).is_none() {
            return Ok(ForeignPacket(self.opts.turn_server, buf.to_vec()));
        } else {
            let rm = self.inflight.remove(&tid);
            if let Some(mut h) = rm.unwrap().completion_hook {
                if let Some(ret) = (*h)(self)? {
                    return Ok(ret);
                }
            }
        }

        if self.when_to_renew_the_allocation.is_none() {
            // Not yet acquired an allocation
            match decoded.class() {
                SuccessResponse => {
                    let ra = decoded.get_attribute::<XorRelayAddress>().ok_or("No XorRelayAddress in reply")?;
                    let ma = decoded.get_attribute::<XorMappedAddress>().ok_or("No XorMappedAddress in reply")?;
                    let sw = decoded.get_attribute::<Software>().as_ref().map(|x|x.description());
                    let lt = decoded.get_attribute::<Lifetime>().ok_or("No Lifetime in reply")?;

                    let lt = self.process_alloc_lifetime(lt.lifetime());

                    /* Big state change */
                    self.when_to_renew_the_allocation = 
                        Some(Delay::new(Instant::now() + lt));
                    /* Big state echange */

                    let ret = AllocationGranted {
                        relay_address: ra.address(),
                        mapped_address: ma.address(),
                        server_software: sw.map(|x|x.to_owned()),
                    };
                    return Ok(ret)
                },
                ErrorResponse => {
                    let ec = decoded.get_attribute::<ErrorCode>()
                            .ok_or("ErrorResponse without ErrorCode?")?.code();

                    match ec {
                        401 => {
                            if self.nonce.is_some() {
                                Err("Authentication failed")?;
                            }

                            let re = decoded.get_attribute::<Realm>()
                                    .ok_or("Missing Realm in NotAuthorized response")?;
                            let no = decoded.get_attribute::<Nonce>()
                                    .ok_or("Missing Nonce in NotAuthorized response")?;
                            
                            self.realm = Some(re.clone());
                            self.nonce = Some(no.clone());

                            self.send_allocate_request(false)?;
                        },
                        300 => {
                            let ta = decoded.get_attribute::<AlternateServer>()
                                    .ok_or("Redirect without AlternateServer")?;
                            return Ok(RedirectedToAlternateServer(ta.address()));
                        },
                        _ => {
                            Err(format!("Unknown error code from TURN: {}", ec))?;
                        }
                    }
                },
                Indication => {
                    Err("Indication when not allocated anything")?
                },
                Request => {
                    Err("Received a Request instead of Response from server")?
                },
            }
        } else {
            // There is an allocation currently
            match decoded.class() {
                SuccessResponse => {
                    match decoded.method() {    
                        REFRESH => {
                            let lt = decoded.get_attribute::<Lifetime>().ok_or("No Lifetime in reply")?;
                            
                            if lt.lifetime() == Duration::from_secs(0) {
                                self.when_to_renew_the_allocation = None;
                                self.shutdown = true;
                                return Ok(MessageFromTurnServer::Disconnected);
                            }

                            let lt = self.process_alloc_lifetime(lt.lifetime());

                            self.when_to_renew_the_allocation = 
                                Some(Delay::new(Instant::now() + lt));
                        },
                        CREATE_PERMISSION => {
                            Err("Reached unreachable code: CREATE_PERMISSION should be handled elsewhere")?
                        },
                        x => {
                            Err(format!("Not implemented: success response for {:?}", x))?
                        },
                    }
                },
                ErrorResponse => {
                    let ec = decoded.get_attribute::<ErrorCode>()
                            .ok_or("ErrorResponse without ErrorCode?")?.code();
                    
                    Err(format!("Error from TURN: {}", ec))?;
                },
                Indication => {
                    Err("Not implemented: handling indications")?
                },
                Request => {
                    Err("Received a Request instead of Response from server")?
                },
            }
            
        }
        
        Ok(MessageFromTurnServer::APacketIsReceivedAndAutomaticallyHandled)
    }
}

impl Stream for TurnClient {
    type Error = Error;
    type Item = MessageFromTurnServer;

    fn poll(&mut self) -> Poll<Option<MessageFromTurnServer>, Error> {
        'main: loop {
            if self.shutdown {
                return Ok(Async::Ready(None));
            }

            let mut buf = [0; 1560];
            // TURN client's jobs (running in parallel):
            // 1. Handle incoming packets
            match self.udp.poll_recv_from(&mut buf[..]) {
                Err(e) => Err(e)?,
                Ok(Async::NotReady) => (),
                Ok(Async::Ready((len, addr))) => {
                    let buf = &buf[0..len];
                    if addr != self.opts.turn_server {
                        return Ok(Async::Ready(Some(MessageFromTurnServer::ForeignPacket(addr,buf.to_vec()))));
                    }
                    let ret = self.handle_incoming_packet(buf)?;
                    return Ok(Async::Ready(Some(ret)));
                },
            }

            // 2. Periodically re-send unreplied requests
            // (includes initial send of any request)
            // TODO: refactor this quadratical complexity
            let mut remove_this_stale_rqs = vec![];
            for (k, rq) in &mut self.inflight {
                match &mut rq.status {
                    InflightRequestStatus::TimedOut => {
                        remove_this_stale_rqs.push(*k);
                    },
                    InflightRequestStatus::SendNow => {
                        match self.udp.poll_send_to(&rq.data[..], &self.opts.turn_server) {
                            Err(e)=>Err(e)?,
                            Ok(Async::NotReady)=>(),
                            Ok(Async::Ready(len)) => {
                                assert_eq!(len, rq.data.len());
                                let d = Delay::new(Instant::now() + self.opts.retry_interval);
                                //let _ = d.poll(); // register it now, don't rely on implicits
                                rq.status = InflightRequestStatus::RetryLater(d);

                                continue 'main;
                            },
                        }
                    },
                    InflightRequestStatus::RetryLater(ref mut d) => {
                        match d.poll() {
                            Err(e)=>Err(e)?,
                            Ok(Async::NotReady)=>(),
                            Ok(Async::Ready(())) => {
                                rq.retryctr += 1;
                                if rq.retryctr >= self.opts.max_retries {
                                    rq.status = InflightRequestStatus::TimedOut;
                                    Err("Request timed out")?;
                                } else {
                                    rq.status = InflightRequestStatus::SendNow;
                                    continue 'main;
                                }
                            }
                        }
                    },
                }
            }
            for rm in remove_this_stale_rqs {
                self.inflight.remove(&rm);
            }

            // 3. Refresh the allocation periodically

            if let Some(x) = &mut self.when_to_renew_the_allocation {
                match x.poll() {
                    Err(e)=>Err(e)?,
                    Ok(Async::NotReady) => (),
                    Ok(Async::Ready(())) => {
                        let ri = self.opts.refresh_interval;
                        x.reset(Instant::now() + ri);
                        self.send_allocate_request(false)?;
                        continue 'main;
                    },
                }
            }

            // 4. Refresh channels and permissions periodically
            let mut ids_to_refresh = vec![];
            if let Some(pp) = &mut self.permissions_pinger {
                match pp.poll() {
                    Err(e)=>Err(e)?,
                    Ok(Async::NotReady) => (),
                    Ok(Async::Ready(_instant)) => {
                        for (h, _) in self.permissions.iter() {
                            ids_to_refresh.push(h);
                        }
                    },
                }
            }
            if !ids_to_refresh.is_empty() {
                for h in ids_to_refresh {
                    // TODO: send multiple addresses per request, not one by one
                    self.send_perm_request(h)?;
                }
                continue 'main;
            }
            

            return Ok(Async::NotReady) // don't care which one in particular is not ready
        } // loop
    }
}

impl Sink for TurnClient {
    type SinkItem = MessageToTurnServer;
    type SinkError = Error;

    fn start_send(&mut self, msg: MessageToTurnServer) -> StartSend<MessageToTurnServer,Error> {
        if self.shutdown {
            return Ok(AsyncSink::Ready);
        }
        use self::MessageToTurnServer::*;
        match msg {
            Noop => (),
            AddPermission(sa, chusage) => {
                if self.permissions_pinger.is_none() {
                    self.permissions_pinger = Some(Interval::new_interval(Duration::from_secs(PERM_REFRESH_INTERVAL)));
                }

                if chusage == ChannelUsage::WithChannel {
                    if self.permissions.len() >= 0x3FFE {
                        Err("There are too many permissions/channels to open another channel")?
                    }
                }

                let p = Permission {
                    addr: sa,
                    channelized: chusage == ChannelUsage::WithChannel,
                    creation_already_reported: false,
                };
                let id = self.permissions.insert(p);
                self.sockaddr2perm.insert(sa, id);
                self.send_perm_request(id)?;
            },
            SendTo(sa, data) => {
                match self.udp.poll_write_ready() {
                    Err(e)=>Err(e)?,
                    Ok(Async::Ready(_))=>(),
                    Ok(Async::NotReady) => {
                        return Ok(AsyncSink::NotReady(SendTo(sa,data)));
                    },
                }
                self.send_data_indication(sa, data)?;
            },
            Disconnect => {
                self.send_allocate_request(true)?;
            },
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(),Error> {
        // I always initially unsure about how to divide work
        // between start_send and poll_complete
        Ok(Async::Ready(()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
