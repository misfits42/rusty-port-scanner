use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::sync::{Arc, Mutex};

const THREAD_CAP: u16 = 100;

fn main() {
    scan_localhost_tcp_ports();
}

/// Conducts a port scan on local computer
fn scan_localhost_tcp_ports() {
    let mut worker_threads: Vec<thread::JoinHandle<()>> = vec![];
    let total_scanned = Arc::new(Mutex::new(0));
    // Spawn all the worker threads
    for i in 1..THREAD_CAP + 1 {
        let total_scanned = Arc::clone(&total_scanned);
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
                    TcpStream::connect(&socket_addr)
                {
                    println!("[+] Connected to {}", &socket_addr);
                }
                // Increment the total number of ports scanned
                let mut num = total_scanned.lock().unwrap();
                *num += 1;
                if (*num % 100) == 0 {
                    println!("Ports scanned: {}", *num);
                }
            }
        }));
    }
    // Join the worker threads
    for worker in worker_threads {
        let _ = worker.join();
    }
}
