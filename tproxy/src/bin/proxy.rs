//! A fake proxy.

extern crate clap;
extern crate nix;
extern crate anyhow;
extern crate ctrlc;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd as _;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use nix::sys::socket::bind;
use nix::sys::socket::listen;
use nix::sys::socket::setsockopt;
use nix::sys::socket::socket;
use nix::sys::socket::sockopt::IpTransparent;
use nix::sys::socket::sockopt::ReuseAddr;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::Backlog;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::SockaddrIn;

/// Fake proxy
///
/// This fake proxy will receive tproxied packets and print some information
/// about the remote peer.
#[derive(Debug, Parser)]
struct Command {
    /// Address the proxy is listening on
    #[arg(long, value_parser, default_value = "10.5.1.9")]
    addr: String,
    /// Port to listen on
    #[arg(long, default_value = "9999")]
    port: u16,
}

fn handle_client(client: TcpStream) -> Result<()> {
    let local_addr = client.local_addr().context("Failed to get local addr")?;
    let peer_addr = client.peer_addr().context("Failed to get peer addr")?;

    println!("New connection:");
    println!("\tlocal: {local_addr}");
    println!("\tpeer: {peer_addr}");
    println!();

    // Clone the stream for reading and writing
    let mut client_read = client.try_clone().context("Failed to clone client stream")?;
    let mut client_write = client;

    // Create a flag to control the communication loop
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    // Spawn a thread to handle incoming messages from the client
    let read_handle = thread::spawn(move || {
        let reader = BufReader::new(&mut client_read);
        for line in reader.lines() {
            match line {
                Ok(message) => {
                    if message.trim().is_empty() {
                        continue;
                    }
                    println!("[Client -> Proxy]: {}", message);
                    
                    // Check for quit command
                    if message.trim().to_lowercase() == "quit" || message.trim().to_lowercase() == "exit" {
                        println!("Client requested to quit");
                        running_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from client: {}", e);
                    running_clone.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Main loop for sending messages to the client
    println!("Interactive mode started. Type messages to send to client, or 'quit' to exit.");
    println!("Commands: 'quit' or 'exit' to close connection");
    println!("----------------------------------------");

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        print!("[Proxy -> Client]: ");
        io::stdout().flush().context("Failed to flush stdout")?;

        let mut input = String::new();
        match stdin_lock.read_line(&mut input) {
            Ok(_) => {
                let message = input.trim();
                if message.is_empty() {
                    continue;
                }

                // Check for quit command
                if message.to_lowercase() == "quit" || message.to_lowercase() == "exit" {
                    println!("Closing connection...");
                    running.store(false, Ordering::SeqCst);
                    break;
                }

                // Send message to client
                if let Err(e) = writeln!(client_write, "{}", message) {
                    eprintln!("Error sending message to client: {}", e);
                    running.store(false, Ordering::SeqCst);
                    break;
                }
                client_write.flush().context("Failed to flush client stream")?;
            }
            Err(e) => {
                eprintln!("Error reading from stdin: {}", e);
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    // Wait for the read thread to finish
    if let Err(e) = read_handle.join() {
        eprintln!("Error joining read thread: {:?}", e);
    }

    println!("Connection closed.");
    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();

    // Create listener socket
    let fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .context("Failed to create listener socket")?;

    // Set some sockopts
    setsockopt(&fd, ReuseAddr, &true).context("Failed to set SO_REUSEADDR")?;
    setsockopt(&fd, IpTransparent, &true).context("Failed to set IP_TRANSPARENT")?;

    // Bind to addr
    let addr = format!("{}:{}", opts.addr, opts.port);
    let addr = SockaddrIn::from_str(&addr).context("Failed to parse socketaddr")?;
    bind(fd.as_raw_fd(), &addr).context("Failed to bind listener")?;

    // Start listening
    listen(&fd, Backlog::new(128).unwrap()).context("Failed to listen")?;
    let listener = TcpListener::from(fd);

    println!("Interactive TProxy server listening on {}:{}", opts.addr, opts.port);
    println!("Waiting for connections...");
    println!("Press Ctrl+C to stop the server");
    println!();

    // Install Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    ctrlc::set_handler(move || {
        println!("\nShutting down server...");
        r.store(false, Ordering::SeqCst);
    })?;

    for client in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match client {
            Ok(client) => {
                if let Err(e) = handle_client(client) {
                    eprintln!("Failed to handle client: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Failed to accept client connection: {}", e);
            }
        }
    }

    println!("Server stopped.");
    Ok(())
}
