use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

pub struct NetworkAnalyzer {
    interface: NetworkInterface,
    received_packets: Arc<Mutex<Vec<(Instant, EthernetPacket)>>>,
}

impl NetworkAnalyzer {
    pub fn new(interface: NetworkInterface) -> Self {
        NetworkAnalyzer {
            interface,
            received_packets: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start_capture(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (_, mut rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => return Err(Box::new(e)),
        };

        let received_packets = Arc::clone(&self.received_packets);
        loop {
            match rx.next() {
                Ok(frame) => {
                    let packet = EthernetPacket::new(frame).unwrap();
                    let timestamp = Instant::now();
                    received_packets.lock().unwrap().push((timestamp, packet));
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    continue;
                }
            }
        }
    }

    pub fn get_packet_statistics(&self) -> BTreeMap<IpAddr, usize> {
        let mut packet_stats = BTreeMap::new();
        let received_packets = self.received_packets.lock().unwrap();

        for (_, packet) in received_packets.iter() {
            if let Some(eth_payload) = EthernetPacket::payload(&packet) {
                if packet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip_packet) = Ipv4Packet::new(eth_payload) {
                        let src = ip_packet.get_source();
                        let dest = ip_packet.get_destination();
                        *packet_stats.entry(src).or_insert(0) += 1;
                        *packet_stats.entry(dest).or_insert(0) += 1;
                    }
                }
            }
        }

        packet_stats
    }
}
