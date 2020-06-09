use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::cmp;
use std::collections::HashMap;
use std::collections::VecDeque;

use clap::{App, Arg};
use indicatif::{ProgressBar, ProgressStyle};

const THREAD_CAP: u16 = 100;

fn main() {
    // Set up command-line argument parser
    let matches = App::new("Rusty Port Scanner")
        .version("0.1.0")
        .about("TCP and UDP port scanner")
        .author("Connor Mooney-Collett")
        .arg(
            Arg::with_name("target")
                .short("T")
                .long("target")
                .value_name("TARGET")
                .help("Scan target")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .value_name("TIMEOUT")
                .help("Timeout for TCP connection in ms")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ports")
                .short("p")
                .long("ports")
                .value_name("PORTS")
                .help("Range of ports to scan")
                .takes_value(true),
        )
        .get_matches();
    // Extract command-line arguments
    let target = matches.value_of("target").unwrap_or("127.0.0.1");
    let timeout_ms = matches
        .value_of("timeout")
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap();
    // Generate the port range to use
    let port_limits_raw = matches
        .value_of("ports")
        .unwrap_or("1-1024")
        .split("-")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    if port_limits_raw.len() > 2 {
        eprintln!("[!] ERROR: Invalid number of port limits. Please provide single port, or lower and upper limit.");
        return;
    }
    let mut port_limits: Vec<u16> = vec![];
    for raw in port_limits_raw {
        // Check if the string represents a valid u16 value
        let convert = raw.parse::<u16>();
        if convert.is_err() {
            eprintln!("[!] ERROR: Invalid port limit format.");
            return;
        }
        // Check if 0 was given
        let convert = convert.unwrap();
        if convert == 0 {
            eprintln!("[!] ERROR: Lower port limit cannot be 0.");
            return;
        }
        port_limits.push(convert);
    }
    // Check that the lower limit is less than or equal to upper limit
    if port_limits.len() == 2 && (port_limits[0] > port_limits[1]) {
        eprintln!("[!] ERROR: Lower port limit must be less than or equal to upper limit.");
        return;
    }
    // Generate range of ports to scan
    let port_range: Vec<u16> = {
        if port_limits.len() == 1 {
            vec![port_limits[0]]
        } else {
            (port_limits[0]..=port_limits[1]).collect()
        }
    };
    // TCP connect scan - target host
    scan_host_tcp_ports(String::from(target), timeout_ms, port_range);
}

/// Conducts a port scan on local computer
fn scan_host_tcp_ports(target: String, timeout_ms: u64, ports: Vec<u16>) {
    println!("Scanning {} ...", target);
    // Initialise array to hold handles to worker threads
    let mut worker_threads: Vec<thread::JoinHandle<()>> = vec![];
    // Initialise variables to be shared across threads
    let progress_bar = Arc::new(Mutex::new(ProgressBar::new(ports.len() as u64)));
    progress_bar.lock().unwrap().set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .progress_chars("#>-"),
    );
    let ports_open = Arc::new(Mutex::new(HashMap::<u16, String>::new()));
    let ports_to_scan = Arc::new(Mutex::new(ports.clone().into_iter().collect::<VecDeque<u16>>()));
    let total_ports: u16 = ports.len() as u16;
    // Calculate number of threads to use
    let total_threads = cmp::min(total_ports, THREAD_CAP);
    // Check if IP address provided is valid
    let ip_addr_result = target.parse::<Ipv4Addr>();
    if ip_addr_result.is_err() {
        eprintln!("[!] ERROR: Invalid IP address format for target.");
        return;
    }
    let ip_addr = IpAddr::V4(ip_addr_result.unwrap());
    // Spawn all the worker threads
    for _ in 0..total_threads {
        // Clone the shared variables
        let progress_bar = Arc::clone(&progress_bar);
        let ports_open = Arc::clone(&ports_open);
        let ports_to_scan = Arc::clone(&ports_to_scan);
        worker_threads.push(thread::spawn(move || {
            loop {
                // Get the next available port
                let pop_result = ports_to_scan.lock().unwrap().pop_front();
                if pop_result == None {
                    break;
                }
                let port = pop_result.unwrap();
                // Create the new connect for connection attempt
                let socket_addr = SocketAddr::new(ip_addr, port);
                // Attempt TCP connection with timeout if specified
                let connect_result = {
                    if timeout_ms == 0 {
                        TcpStream::connect(&socket_addr)
                    } else {
                        TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms))
                    }
                };
                // Check if the connection attempt was successful or not
                if connect_result.is_ok() {
                    // TODO: Conduct banner grab

                    // Record port as being open
                    ports_open.lock().unwrap().insert(port, String::from(""));
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
    let ports_open = Arc::try_unwrap(ports_open).unwrap().into_inner().unwrap();
    let mut ordered_ports_open = ports_open.keys().map(|x| *x).collect::<Vec<u16>>();
    ordered_ports_open.sort();
    for port in ordered_ports_open {
        println!("[+] OPEN - tcp/{}", port);
    }
}
