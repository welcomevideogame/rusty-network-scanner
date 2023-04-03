use smoltcp::iface::{EthernetInterface, EthernetInterfaceBuilder, Neighbor, NeighborCache, Routes};
use smoltcp::phy::{Device, Medium};
use smoltcp::socket::SocketSet;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, Ipv4Address, Ipv4Packet, TcpPacket, TcpRepr};
use std::collections::BTreeMap;
use std::io::{stdin, stdout, Write};
use std::sync::Arc;
use std::str::FromStr;
use tokio::runtime::Runtime;
use tuntap::{Iface, Mode};

pub fn start_scanner() {
    let device = get_network_interface();
    let (iface, mut socket_set) = create_ethernet_interface(device);

    let mut rt = Runtime::new().unwrap();

    rt.block_on(async {
        let mut iface = iface.finalize(());

        loop {
            let timestamp = Instant::from_millis(0);

            match iface.poll(&mut socket_set, timestamp) {
                Ok(_) => (),
                Err(e) => eprintln!("Error: {}", e),
            }

            let mut buffer = [0u8; 2048];
            let frame = match iface.recv(&mut buffer) {
                Ok(frame) => frame,
                Err(_) => continue,
            };

            process_frame(frame);
        }
    });
}

fn process_frame(frame: &[u8]) {
    let eth_frame = EthernetFrame::new_checked(frame).unwrap();
    let protocol = input_protocol();
    if eth_frame.ethertype() == protocol {
        match protocol {
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(eth_frame.payload()).unwrap();
                print_ipv4_packet_info(&ipv4_packet);
            }
            // Add more protocols and their respective processing functions here.
            _ => (),
        }
    }
}

fn input_protocol() -> EthernetProtocol {
    let mut input = String::new();
    print!("Enter protocol to filter (e.g., Ipv4): ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).unwrap();
    EthernetProtocol::from_str(input.trim()).unwrap_or(EthernetProtocol::Ipv4)
}

fn print_ipv4_packet_info(packet: &Ipv4Packet<&[u8]>) {
    println!("IP: {}", packet.source_addr());
    println!("Protocol: {:?}", packet.protocol());
    println!("TTL: {}", packet.hop_limit());
    println!("Payload Length: {}", packet.payload().len());
}

fn get_network_interface() -> Arc<dyn Device> {
    let interface_name = get_interface_name();
    let iface = Iface::without_packet_info(&interface_name, Mode::TunTap).expect("Failed to create TUN/TAP interface");
    Arc::new(iface)
}

fn get_interface_name() -> String {
    String::new()
}

fn create_ethernet_interface(
    device: Arc<dyn Device>,
) -> (
    EthernetInterfaceBuilder<'static, 'static, Arc<dyn Device>>,
    SocketSet<'static, 'static, 'static>,
) {
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let ipv4_addr = Ipv4Address::new(0, 0, 0, 0);
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let routes = Routes::new(BTreeMap::new());
    let iface_builder = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(ethernet_addr)
        .ipv4_addr(ipv4_addr)
        .neighbor_cache(neighbor_cache)
        .routes(routes);
    let socket_set = SocketSet::new(vec![]);
    (iface_builder, socket_set)
}

pub fn sniff_http_request(packet: &Ipv4Packet<&[u8]>) -> Option<String> {
    if packet.protocol() != smoltcp::wire::IpProtocol::Tcp {
        return None;
    }

    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();
    let tcp_repr = TcpRepr::parse(&tcp_packet, &packet.src_addr(), &packet.dst_addr()).unwrap();

    if tcp_repr.dst_port != 80 {
        return None;
    }

    let payload = tcp_packet.payload();
    let request = String::from_utf8_lossy(payload);
    if request.starts_with("GET") || request.starts_with("POST") || request.starts_with("HEAD") {
        Some(request.to_string())
    } else {
        None
    }
}

pub fn sniff_http_response(packet: &Ipv4Packet<&[u8]>) -> Option<String> {
    if packet.protocol() != smoltcp::wire::IpProtocol::Tcp {
        return None;
    }

    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();
    let tcp_repr = TcpRepr::parse(&tcp_packet, &packet.src_addr(), &packet.dst_addr()).unwrap();

    if tcp_repr.src_port != 80 {
        return None;
    }

    let payload = tcp_packet.payload();
    let response = String::from_utf8_lossy(payload);
    if response.starts_with("HTTP") {
        Some(response.to_string())
    } else {
        None
    }
}

pub fn sniff_tcp_packet(packet: &Ipv4Packet<&[u8]>) -> Option<TcpRepr> {
    if packet.protocol() != smoltcp::wire::IpProtocol::Tcp {
        return None;
    }

    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();
    let tcp_repr = TcpRepr::parse(&tcp_packet, &packet.src_addr(), &packet.dst_addr()).unwrap();
    Some(tcp_repr)
}