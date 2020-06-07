use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Arg, App, SubCommand};
use indicatif::{ProgressBar, ProgressStyle};

const THREAD_CAP: u16 = 100;

fn main() {
    // Process command line arguments
    let matches = App::new("Rusty Port Scanner")
                        .version("0.1.0")
                        .about("TCP and UDP port scanner")
                        .author("Connor Mooney-Collett")
                        .get_matches();
    // TEST - scan localhost TCP ports
    scan_localhost_tcp_ports();
}

/// Conducts a port scan on local computer
fn scan_localhost_tcp_ports() {
    // Initialise array to hold handles to worker threads
    let mut worker_threads: Vec<thread::JoinHandle<()>> = vec![];
    // Initialise variables to be shared across threads
    println!("Scanning 127.0.0.1 ...");
    let progress_bar = Arc::new(Mutex::new(ProgressBar::new(65535)));
    progress_bar.lock().unwrap().set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .progress_chars("#>-"));
    let ports_open = Arc::new(Mutex::new(Vec::<u16>::new()));
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
                let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                if let Ok(_stream) =
                    TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100))
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
