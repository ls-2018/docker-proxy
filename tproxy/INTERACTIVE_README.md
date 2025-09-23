# Interactive TProxy Example

This example demonstrates an interactive transparent proxy that allows bidirectional communication between the proxy server and clients.

## Features

- **Interactive Communication**: The proxy now supports sending and receiving messages interactively
- **Bidirectional Messaging**: Both the proxy and client can send messages to each other
- **Connection Management**: Proper handling of connection establishment and teardown
- **Graceful Shutdown**: Support for quit/exit commands and Ctrl+C handling

## How to Use

### 1. Build the Example

```bash
cargo build --release
```

### 2. Start the TProxy Server

First, start the main tproxy program that sets up the BPF program:

```bash
sudo ./target/release/tproxy --port 1003 --proxy-addr 10.5.1.9 --proxy-port 9999
```

### 3. Start the Interactive Proxy Server

In another terminal, start the interactive proxy server:

```bash
./target/release/proxy --addr 10.5.1.9 --port 9999
```

### 4. Test the Connection

You can test the interactive functionality using the provided Python test client:

```bash
python3 test_client.py 127.0.0.1 1003
```

Or use any TCP client (like `telnet` or `nc`):

```bash
telnet 127.0.0.1 1003
```

## Interactive Commands

- **Normal Messages**: Type any message and press Enter to send it to the client
- **Quit/Exit**: Type `quit` or `exit` to close the connection
- **Ctrl+C**: Press Ctrl+C to stop the proxy server

## How It Works

1. **BPF Program**: The `tproxy.bpf.c` program intercepts packets destined for the target port (1003) and redirects them to the proxy server (port 9999)

2. **Interactive Proxy**: The `proxy.rs` program:
   - Listens on the proxy port (9999) with IP_TRANSPARENT socket option
   - Accepts redirected connections from the BPF program
   - Spawns a separate thread to handle incoming messages from clients
   - Provides an interactive interface for sending messages to clients
   - Handles graceful connection termination

3. **Message Flow**:
   - Client connects to port 1003
   - BPF program redirects the connection to the proxy on port 9999
   - Proxy establishes interactive communication with the client
   - Both proxy and client can send messages to each other

## Example Session

```
$ ./target/release/proxy --addr 10.5.1.9 --port 9999
Interactive TProxy server listening on 10.5.1.9:9999
Waiting for connections...
Press Ctrl+C to stop the server

New connection:
        local: 127.0.0.1:9999
        peer: 127.0.0.1:54321

Interactive mode started. Type messages to send to client, or 'quit' to exit.
Commands: 'quit' or 'exit' to close connection
----------------------------------------
[Proxy -> Client]: Hello from proxy!
[Client -> Proxy]: Hello from client!
[Proxy -> Client]: How are you?
[Client -> Proxy]: I'm doing well, thank you!
[Proxy -> Client]: quit
Closing connection...
Connection closed.
```

## Troubleshooting

- **Permission Issues**: Make sure to run the tproxy program with `sudo` as it requires root privileges to attach BPF programs
- **Port Conflicts**: Ensure the ports (1003 and 9999) are not already in use
- **Connection Issues**: Check that both the tproxy and proxy programs are running before testing with a client
