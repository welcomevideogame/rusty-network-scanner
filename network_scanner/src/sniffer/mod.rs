use smoltcp::wire::{Ipv4Packet, UdpPacket};

pub fn start_sniffer(interface_name: &str, protocol: Option<EthernetProtocol>) -> Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut cap = Capture::from_device(Device::lookup().unwrap().unwrap().name.as_str())
            .unwrap()
            .promisc(true)
            .open()
            .unwrap();

        loop {
            match cap.next() {
                Ok(packet) => {
                    if let Some(protocol) = protocol {
                        let eth_frame = EthernetFrame::new_checked(&packet).unwrap();
                        if eth_frame.ethertype() != protocol {
                            continue;
                        }
                    }
                    tx.send(packet.to_vec()).unwrap();
                    if let Some(protocol) = protocol {
                        if protocol == EthernetProtocol::Ipv4 {
                            let ipv4_packet = Ipv4Packet::new(&packet).unwrap();
                            print_ipv4_packet_info(&ipv4_packet);
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    } else {
                        break;
                    }
                }
            }
        }
    });

    rx
}

fn print_ipv4_packet_info(packet: &Ipv4Packet<&[u8]>) {
    println!("IP: {}", packet.source_addr());
    println!("Protocol: {:?}", packet.protocol());
    println!("TTL: {}", packet.hop_limit());
    println!("Payload Length: {}", packet.payload().len());
}

pub fn decode_dns_packet(packet: &Ipv4Packet<&[u8]>, udp_packet: &UdpPacket<&[u8]>) -> Option<String> {
    let payload = udp_packet.payload();
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let qr = (payload[2] & 0x80) != 0;
    if !qr {
        return None;
    }
    let opcode = (payload[2] & 0x78) >> 3;
    if opcode != 0 {
        return None;
    }
    let aa = (payload[2] & 0x04) != 0;
    let tc = (payload[2] & 0x02) != 0;
    let rd = (payload[2] & 0x01) != 0;
    let ra = (payload[3] & 0x80) != 0;
    let rcode = payload[3] & 0x0f;
    if rcode != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount != 1 {
        return None;
    }
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);
    let mut offset = 12;
    let mut domain_name = String::new();
    loop {
        let label_length = payload[offset] as usize;
        if label_length == 0 {
            break;
        }
        if (label_length & 0xc0) == 0xc0 {
            offset += 2;
            break;
        }
        offset += 1;
        for i in 0..label_length {
            domain_name.push(payload[offset + i] as char);
        }
        domain_name.push('.');
        offset += label_length;
    }
    domain_name.pop();
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
    offset += 4;
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let answer_offset = offset;
        if let Some((name, offset)) = decode_domain_name(payload, answer_offset) {
            let atype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let aclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let ttl = u32::from_be_bytes([
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]);
            offset += 10;
            let rdata = &payload[offset..offset + rdlength as usize];
            offset += rdlength as usize;
            answers.push((name, atype, aclass, ttl, rdata.to_vec()));
        } else {
            return None;
        }
    }
    let mut additional_records = Vec::new();
    for _ in 0..arcount {
        let answer_offset = offset;
        if let Some((name, offset)) = decode_domain_name(payload, answer_offset) {
            let atype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let aclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let ttl = u32::from_be_bytes([
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]);
            offset += 10;
            let rdata = &payload[offset..offset + rdlength as usize];
            offset += rdlength as usize;
            additional_records.push((name, atype, aclass, ttl, rdata.to_vec()));
        } else {
            return None;
        }
    }
    let response = format!(
        "DNS id={}, qr={}, opcode={}, aa={}, tc={}, rd={}, ra={}, rcode={}, qdcount={}, ancount={}, nscount={}, arcount={}, name={}, qtype={}, qclass={}",
        id,
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
        domain_name,
        qtype,
        qclass
    );
    Some(response)
}

fn decode_domain_name<'a>(payload: &'a [u8], mut offset: usize) -> Option<(String, usize)> {
    let mut domain_name = String::new();
    let mut loop_detected = false;
    loop {
        let label_length = payload[offset] as usize;
        if label_length == 0 {
            break;
        }
        if loop_detected {
            return None;
        }
        if (label_length & 0xc0) == 0xc0 {
            let pointer = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let pointer = pointer & 0x3fff;
            if let Some((pointer_name, _)) = decode_domain_name(payload, pointer as usize) {
                domain_name.push_str(&pointer_name);
            }
            offset += 2;
            break;
        }
        offset += 1;
        for i in 0..label_length {
            domain_name.push(payload[offset + i] as char);
        }
        domain_name.push('.');
        offset += label_length;
        if offset >= payload.len() {
            return None;
        }
        if payload[offset] == 0xc0 {
            loop_detected = true;
        }
    }
    domain_name.pop();
    Some((domain_name, offset))
}

pub fn decode_http_packet(packet: &[u8]) -> Option<String> {
    let http_packet = HttpPacket::new(packet).ok()?;
    let request_line = match http_packet.first_line() {
        HttpFirstLine::Request(request_line) => request_line,
        _ => return None,
    };
    let method = request_line.method().map(|method| method.to_string()).unwrap_or_else(|| "".to_string());
    let uri = request_line.uri().map(|uri| uri.to_string()).unwrap_or_else(|| "".to_string());
    let version = request_line.version().map(|version| version.to_string()).unwrap_or_else(|| "".to_string());
    let mut headers = String::new();
    for header in http_packet.headers() {
        if let Some(name) = header.name() {
            if let Ok(value) = header.value() {
                headers += &format!("{}: {}\r\n", name, value);
            }
        }
    }
    let mut body = Vec::new();
    if let Ok(payload) = http_packet.payload() {
        body.extend_from_slice(payload);
    }
    let response = format!(
        "HTTP method={}, uri={}, version={}\r\nHeaders:\r\n{}\r\nBody:\r\n{:?}",
        method, uri, version, headers, body
    );
    Some(response)
}

use smoltcp::wire::{EthernetFrame, EthernetProtocol, Ipv4Packet, TcpPacket, TcpRepr};

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
