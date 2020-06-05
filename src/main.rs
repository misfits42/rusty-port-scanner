use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

fn main() {
    scan_localhost_tcp_ports();
}

/// Conducts a port scan on local computer
fn scan_localhost_tcp_ports() {
    for port in 1..=65535 {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        if let Ok(_stream) = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(5)) {
            println!("connected to {}", &socket_addr);
        }
    }
}
