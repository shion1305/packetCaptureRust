extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{ip, tcp, udp, Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::datalink::Channel::Ethernet;

fn main() {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .find(|iface: &NetworkInterface| iface.is_up() && !iface.is_loopback())
                              .expect("Cannot find interface");

    // インタフェースを通じてデータをキャプチャする
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                match packet.get_ethertype() {
                    EtherTypes::Ipv4 => handle_ipv4_packet(&packet),
                    // 他のイーサネットタイプを処理したい場合、ここに処理を追加する
                    _ => (),
                }
            },
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) {
    if let Some(header) = ip::Ipv4Packet::new(ethernet.payload()) {
        match header.get_next_level_protocol() {
            ip::IpNextHeaderProtocols::Tcp => {
                let tcp = tcp::TcpPacket::new(header.payload());
                if let Some(tcp) = tcp {
                    println!("TCP Packet: {}:{} to {}:{}; length: {}",
                             header.get_source(), tcp.get_source(),
                             header.get_destination(), tcp.get_destination(),
                             header.get_total_length());
                }
            },
            ip::IpNextHeaderProtocols::Udp => {
                let udp = udp::UdpPacket::new(header.payload());
                if let Some(udp) = udp {
                    println!("UDP Packet: {}:{} to {}:{}; length: {}",
                             header.get_source(), udp.get_source(),
                             header.get_destination(), udp.get_destination(),
                             header.get_length());
                }
            },
            _ => (),
        }
    }
}

