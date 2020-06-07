use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Arg, App};
use indicatif::{ProgressBar, ProgressStyle};

const THREAD_CAP: u16 = 100;

fn main() {
    // Set up command-line argument parser
    let matches = App::new("Rusty Port Scanner")
                        .version("0.1.0")
                        .about("TCP and UDP port scanner")
                        .author("Connor Mooney-Collett")
                        .arg(Arg::with_name("target")
                            .short("t")
                            .long("target")
                            .value_name("TARGET")
                            .help("Scan target")
                            .takes_value(true))
                        .arg(Arg::with_name("timeout")
                            .short("to")
                            .long("timeout")
                            .value_name("TIMEOUT")
                            .help("Timeout for TCP connection in ms")
                            .takes_value(true))
                        .get_matches();
    // Extract command-line arguments
    let target = matches.value_of("target").unwrap_or("127.0.0.1");
    let timeout_ms = matches.value_of("timeout").unwrap_or("0").parse::<u64>().unwrap();
    // TEST - scan localhost TCP ports
    scan_host_tcp_ports(String::from(target), timeout_ms);
}

/// Conducts a port scan on local computer
fn scan_host_tcp_ports(target: String, timeout_ms: u64) {
    println!("Scanning {} ...", target);
    // Initialise array to hold handles to worker threads
    let mut worker_threads: Vec<thread::JoinHandle<()>> = vec![];
    // Initialise variables to be shared across threads
    let progress_bar = Arc::new(Mutex::new(ProgressBar::new(65535)));
    progress_bar.lock().unwrap().set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .progress_chars("#>-"));
    let ports_open = Arc::new(Mutex::new(Vec::<u16>::new()));
    // Check if IP address provided is valid
    let ip_addr_result = target.parse::<Ipv4Addr>();
    if ip_addr_result.is_err() {
        eprintln!("[!] ERROR: Invalid IP address format for target.");
        return;
    }
    let ip_addr = IpAddr::V4(ip_addr_result.unwrap());
    // Spawn all the worker threads
    for i in 1..THREAD_CAP + 1 {
        // Clone the shared variables
        let progress_bar = Arc::clone(&progress_bar);
        let ports_open = Arc::clone(&ports_open);
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
                let socket_addr = SocketAddr::new(ip_addr, port);
                let connect_result = {
                    if timeout_ms == 0 {
                        TcpStream::connect(&socket_addr)
                    } else {
                        TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms))
                    }
                };

                if let Ok(_stream) =
                    TcpStream::connect(&socket_addr)
                {
                    // Add the port to the open list
                    ports_open.lock().unwrap().push(port);
                }
                // Increment the total number of ports scanned
                let pb = progress_bar.lock().unwrap();
                pb.inc(1);
            }
        }));
    }
    // Join the worker threads
    for worker in worker_threads {
        let _ = worker.join();
    }
    // Finish the progress bar
    let pb = progress_bar.lock().unwrap();
    pb.finish();
    // Unwrap the Arc and mutex to get the ports opened
    let mut ports_open = Arc::try_unwrap(ports_open).unwrap().into_inner().unwrap();
    ports_open.sort();
    for port in ports_open.iter() {
        println!("[+] OPEN - tcp/{}", port);
    }
}
