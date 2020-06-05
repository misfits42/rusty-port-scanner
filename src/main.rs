use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

const THREAD_CAP: u16 = 100;

fn main() {
    scan_localhost_tcp_ports();
}

/// Conducts a port scan on local computer
fn scan_localhost_tcp_ports() {
    let mut worker_threads: Vec<thread::JoinHandle<()>> = vec![];
    // Spawn all the worker threads
    for i in 1..THREAD_CAP + 1 {
        worker_threads.push(thread::spawn(move || {
            // Calculate the start and end points to cover entire range of ports over all threads
            let start_port = (65535 / (THREAD_CAP - 1)) * (i - 1) + 1;
            let end_port = {
                if (65535 - start_port) < (65535 / (THREAD_CAP - 1)) {
                    65535
                } else {
                    start_port + (65535 / (THREAD_CAP - 1)) - 1
                }
            };
            // Scan all TCP ports allocated to the thread
            for port in start_port..=end_port {
                let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                if let Ok(_stream) =
                    TcpStream::connect_timeout(&socket_addr, Duration::from_millis(10))
                {
                    println!("[+] Connected to {}", &socket_addr);
                }
            }
        }));
    }
    // Join the worker threads
    for worker in worker_threads {
        let _ = worker.join();
    }
}
