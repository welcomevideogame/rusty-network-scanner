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

pub fn print_tcp_payload(&self) {
    let received_packets = self.received_packets.lock().unwrap();

    for (_, packet) in received_packets.iter() {
        if let Some(eth_payload) = EthernetPacket::payload(&packet) {
            if packet.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(ip_packet) = Ipv4Packet::new(eth_payload) {
                    if ip_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                        if tcp_packet.get_payload().len() > 0 {
                            let payload_str = str::from_utf8(tcp_packet.get_payload()).unwrap();
                            println!("{}", payload_str);
                        }
                    }
                }
            }
        }
    }
}

pub fn get_top_n_packets(&self, n: usize) -> Vec<(IpAddr, usize)> {
    let packet_stats = self.get_packet_statistics();
    let mut heap = BinaryHeap::new();

    for (ip_addr, packet_count) in packet_stats.iter() {
        if heap.len() < n {
            heap.push(Reverse((packet_count, ip_addr.clone())));
        } else if *packet_count > heap.peek().unwrap().0 {
            heap.pop();
            heap.push(Reverse((packet_count, ip_addr.clone())));
        }
    }

    heap.into_sorted_vec().into_iter().map(|rev| (rev.1, rev.0)).collect()
}

pub fn get_packet_count(&self, ip_addr: IpAddr) -> usize {
    let packet_stats = self.get_packet_statistics();

    *packet_stats.get(&ip_addr).unwrap_or(&0)
}

pub fn count_tcp_payload_chars(&self) -> HashMap<char, usize> {
    let mut char_counts: HashMap<char, usize> = HashMap::new();
    let mut seen_payloads: HashSet<Vec<u8>> = HashSet::new();

    let received_packets = self.received_packets.lock().unwrap();
    for (_, packet) in received_packets.iter() {
        if let Some(eth_payload) = EthernetPacket::payload(&packet) {
            if packet.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(ip_packet) = Ipv4Packet::new(eth_payload) {
                    if ip_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                        if tcp_packet.get_payload().len() > 0 {
                            if seen_payloads.insert(tcp_packet.get_payload().to_vec()) {
                                for b in tcp_packet.get_payload().iter() {
                                    if (*b as char).is_ascii() {
                                        let count = char_counts.entry(*b as char).or_insert(0);
                                        *count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    char_counts
}
