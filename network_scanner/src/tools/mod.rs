use std::net::{Ipv4Addr, TcpStream};
use std::time::Duration;
use std::io::ErrorKind;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::from_utf8;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Receiver};

pub fn is_port_open(ip: Ipv4Addr, port: u16) -> bool {
    match TcpStream::connect_timeout(&(ip, port).into(), Duration::from_secs(1)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ip::MutableIpv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::icmp_packet_iter;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::{self, TransportChannel};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub fn traceroute(ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let (mut tx, mut rx) = icmp_packet_iter(
        transport::transport_channel(1024, Layer4(IpNextHeaderProtocols::Icmp)),
        Default::default(),
    )
    .unwrap();

    let mut ttl = 1;
    let mut addresses = Vec::new();
    loop {
        let mut ipv4_packet = MutableIpv4Packet::new(vec![0; 20]).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(ipv4_packet.packet_size() as u16);
        ipv4_packet.set_ttl(ttl);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_destination(ip);

        let mut echo_request_packet = MutableEchoRequestPacket::new(vec![0; 8]).unwrap();
        echo_request_packet.set_identifier(0);
        echo_request_packet.set_sequence_number(0);

        let checksum = !IcmpPacket::compute_checksum(
            IcmpPacket::new(echo_request_packet.packet_mut()).unwrap(),
        );
        echo_request_packet.set_checksum(checksum);

        ipv4_packet.set_payload(echo_request_packet.packet());

        tx.send_to(ipv4_packet, ip.into()).unwrap();

        let start = Instant::now();
        match rx.next_with_timeout(Duration::from_secs(1)) {
            Ok((packet, _)) => {
                let icmp_packet = IcmpPacket::new(packet.payload()).unwrap();
                if icmp_packet.get_icmp_type() == pnet::packet::icmp::IcmpType::EchoReply {
                    let ipv4_packet = IpNextHeaderProtocols::Ipv4
                        .packet(packet.payload())
                        .unwrap();
                    let source = ipv4_packet.get_source();
                    addresses.push(source);
                    if source == ip {
                        break;
                    }
                }
            }
            Err(_) => (),
        }
        ttl += 1;
        if ttl > 30 {
            break;
        }
    }
    addresses
}

pub fn syn_scan(ip: Ipv4Addr, start_port: u16, end_port: u16, thread_count: usize) -> Vec<u16> {
    let (sender, receiver) = channel();

    for _ in 0..thread_count {
        let sender = sender.clone();
        thread::spawn(move || loop {
            let port = match sender.recv() {
                Ok(port) => port,
                Err(_) => return,
            };

            let result = match TcpStream::connect_timeout(&(ip, port).into(), Duration::from_secs(1)) {
                Ok(_) => Some(port),
                Err(e) => {
                    if e.kind() == ErrorKind::TimedOut {
                        None
                    } else {
                        Some(port)
                    }
                }
            };

            if let Some(port) = result {
                sender.send(port).unwrap();
            }
        });
    }

    for port in start_port..=end_port {
        sender.send(port).unwrap();
    }

    drop(sender);

    let mut open_ports = Vec::new();
    for port in receiver {
        open_ports.push(port);
    }

    open_ports
}

pub fn ping_sweep(cidr: &str, thread_count: usize) -> Vec<Ipv4Addr> {
    let (sender, receiver) = channel();

    let cidr: IpAddr = cidr.parse().unwrap();
    let prefix_len = match cidr {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 64,
    };
    let netmask = (0..32).fold(0u32, |acc, i| {
        if i < prefix_len {
            acc | 1 << (31 - i)
        } else {
            acc
        }
    });

    for _ in 0..thread_count {
        let sender = sender.clone();
        thread::spawn(move || loop {
            let ip = match sender.recv() {
                Ok(ip) => ip,
                Err(_) => return,
            };

            if let Ok(_) = ping(ip) {
                sender.send(ip).unwrap();
            }
        });
    }

let mut ips_to_ping = Vec::new();
for i in 0..=255 {
    let ip = match cidr {
        IpAddr::V4(ipv4) => Ipv4Addr::new(
            (ipv4.octets()[0] & (netmask >> 24) as u8) | (i as u8 & !(netmask >> 24) as u8),
            (ipv4.octets()[1] & (netmask >> 16) as u8) | (i as u8 & !(netmask >> 16) as u8),
            (ipv4.octets()[0] & (netmask >> 16) as u8) | (i as u8 & !(netmask >> 16) as u8),
            (ipv4.octets()[1] & (netmask >> 8) as u8) | (i as u8 & !(netmask >> 8) as u8),
            (ipv4.octets()[2] & netmask as u8) | (i as u8 & !netmask as u8),
            ),
            IpAddr::V6(_) => unimplemented!(),
        };
        ips_to_ping.push(ip);
    }

    for ip in ips_to_ping {
        sender.send(ip).unwrap();
    }

    drop(sender);

    let mut live_ips = Vec::new();
    for ip in receiver {
        live_ips.push(ip);
    }

    live_ips
}
    
fn ping(ip: Ipv4Addr) -> Result<(), String> {
    let icmp_socket = pnet::transport::icmp_socket().unwrap();
    icmp_socket.set_timeout(Duration::from_secs(1)).unwrap();

    let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(vec![0; 64]).unwrap();
    icmp_packet.set_identifier(0x0);
    icmp_packet.set_sequence_number(0x0);

    let checksum = !pnet::packet::icmp::checksum(&pnet::packet::icmp::IcmpPacket::new(&icmp_packet.packet()).unwrap());
    icmp_packet.set_checksum(checksum);

    let icmp_packet = icmp_packet.into_immutable();

    match pnet::transport::send_to(&icmp_socket, icmp_packet, IpAddr::V4(ip).into()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
pub fn run_nmap(ip: Ipv4Addr) -> String {
    let output = Command::new("nmap")
        .arg("-p-")
        .arg(ip.to_string())
        .output()
        .expect("failed to execute process");

    from_utf8(&output.stdout).unwrap().to_string()
}
    
pub fn dns_lookup(hostname: &str) -> Option<Ipv4Addr> {
    match dns_lookup::lookup_host(hostname) {
        Ok(addresses) => addresses
            .iter()
            .find(|addr| matches!(addr, std::net::IpAddr::V4(_)))
            .map(|addr| *addr.to_ipv4().unwrap()),
        Err(_) => None,
    }
}
    
pub fn in_subnet(ip: Ipv4Addr, subnet: &str) -> bool {
    let (subnet, cidr) = subnet.split_once('/').unwrap();
    let subnet_mask = u32::from_str_radix(subnet.split('.').map(|octet| format!("{:08b}", octet)).collect::<Vec<String>>().join("").as_str(), 2).unwrap();
    let cidr = cidr.parse::<u32>().unwrap();
    let ip = u32::from_be_bytes(ip.octets());
    let subnet = u32::from_be_bytes(Ipv4Addr::from(subnet.parse::<u32>().unwrap()).octets());
    let mask = (0..32).fold(0u32, |acc, i| acc | (if i < cidr { 1 } else { 0 } << (31 - i)));
    (ip & mask) == (subnet & mask)
}