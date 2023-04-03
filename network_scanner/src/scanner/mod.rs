use smoltcp::iface::{EthernetInterface, EthernetInterfaceBuilder, Neighbor, NeighborCache, Routes};
use smoltcp::phy::{Device, Medium};
use smoltcp::socket::SocketSet;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, Ipv4Address, Ipv4Packet};
use std::collections::BTreeMap;
use std::io::{stdin, stdout, Write};
use std::sync::Arc;
use std::str::FromStr;
use tokio::runtime::Runtime;
use tuntap::{Iface, Mode};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::transport::{icmp_packet_iter, transport_channel};
use pnet::transport::TransportChannelType::Layer4;
use std::net::{Ipv4Addr, ToSocketAddrs};
use dns_lookup::lookup_addr;
use std::io::ErrorKind;
use reqwest::blocking::get;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;


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

fn scan_open_ports(ip: IpAddr, start_port: u16, end_port: u16, timeout: Duration) -> Vec<u16> {
    let mut open_ports = Vec::new();
    for port in start_port..=end_port {
        let socket_addr = SocketAddr::new(ip, port);
        if let Ok(stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
            open_ports.push(port);
            stream.shutdown(std::net::Shutdown::Both).expect("shutdown failed");
        }
    }
    open_ports
}

fn icmp_ping(ip: Ipv4Addr, timeout: Duration) -> bool {
    let (mut tx, mut rx) = transport_channel(4096, Layer4(IpNextHeaderProtocols::Icmp))
        .expect("Failed to create transport channel");

    let mut echo_request_buffer = [0u8; MutableEchoRequestPacket::minimum_packet_size()];
    let mut echo_request_packet = MutableEchoRequestPacket::new(&mut echo_request_buffer)
        .expect("Failed to create Echo Request packet");
    echo_request_packet.set_icmp_type(IcmpTypes::EchoRequest);

    let mut ipv4_buffer = [0u8; MutableIpv4Packet::minimum_packet_size()];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer)
        .expect("Failed to create IPv4 packet");
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

    tx.send_to(echo_request_packet.packet(), ip.into())
        .expect("Failed to send Echo Request packet");

    let mut iter = icmp_packet_iter(&mut rx);
    for (packet, _) in iter {
        if packet.get_icmp_type() == IcmpTypes::EchoReply {
            return true;
        }
    }

    false
}  

fn dns_lookup(domain: &str) -> Result<Vec<IpAddr>, io::Error> {
    let socket_addrs = (domain, 0).to_socket_addrs()?;
    let ips: Vec<IpAddr> = socket_addrs.map(|addr| addr.ip()).collect();
    Ok(ips)
}

fn reverse_dns_lookup(ip: &IpAddr) -> Result<String, io::Error> {
    let hostname = lookup_addr(ip)?;
    Ok(hostname)
}

fn is_port_filtered(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let socket_addr = SocketAddr::new(ip, port);
    let tcp_result = TcpStream::connect_timeout(&socket_addr, timeout);
    match tcp_result {
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => true,
        _ => false,
    }
}

fn get_public_ip() -> Result<IpAddr, reqwest::Error> {
    let response = get("https://api.ipify.org")?;
    let ip_string = response.text()?;
    let ip = IpAddr::from_str(&ip_string).unwrap();
    Ok(ip)
}

fn resolve_with_dns_server(domain: &str, dns_server: IpAddr) -> Result<Vec<IpAddr>, io::Error> {
    let mut config = ResolverConfig::new();
    config.add_name_server(dns_server.into());

    let resolver = Resolver::new(config, ResolverOpts::default())?;
    let response = resolver.lookup_ip(domain)?;

    Ok(response.iter().collect())
}