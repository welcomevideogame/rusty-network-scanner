use smoltcp::iface::{EthernetInterface, EthernetInterfaceBuilder, Neighbor, NeighborCache, Routes};
use smoltcp::phy::{Device, Medium};
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, Ipv4Address};
use std::collections::BTreeMap;
use std::io::{stdin, stdout, Write};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tuntap::{Iface, Mode};

pub fn start_scanner() {
    let device = get_network_interface();
    let (iface, mut socket_set) = create_ethernet_interface(device);

    let mut rt = Runtime::new().unwrap();

    rt.block_on(async {
        let mut iface = iface.finalize(());

        loop {
            let timestamp = smoltcp::time::Instant::from_millis(0);

            match iface.poll(&mut socket_set, timestamp) {
                Ok(_) => (),
                Err(e) => eprintln!("Error: {}", e),
            }

            let mut buffer = [0u8; 2048];
            let frame = match iface.recv(&mut buffer) {
                Ok(frame) => frame,
                Err(_) => continue,
            };

            let eth_frame = EthernetFrame::new_checked(frame).unwrap();
            if eth_frame.ethertype() == EthernetProtocol::Ipv4 {
                let ipv4_packet = smoltcp::wire::Ipv4Packet::new(eth_frame.payload()).unwrap();
                println!("IP: {}", ipv4_packet.source_addr());
            }
        }
    });
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
    smoltcp::socket::SocketSet<'static, 'static, 'static>,
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
    let socket_set = smoltcp::socket::SocketSet::new(vec![]);
    (iface_builder, socket_set)
}
