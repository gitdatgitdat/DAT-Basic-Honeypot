# DAT Basic Honeypot

Basic Python honeypot that listens on configurable ports, logs all inbound connections, and captures any payloads sent by clients.
Built as a security learning project to explore deception, incident detection, and logging fundamentals.

---

## Features

Listens on one or more TCP ports of your choice

Logs connection metadata:

Timestamp (UTC)

Local port and remote IP/port

Bytes captured

Stores payloads as hex (and optionally preview as ASCII)

Lightweight, runs on standard Python (no external dependencies)

Useful for practicing detection, response, and adversary emulation

---

## Requirements

Python 3.11+

Windows, Linux, or macOS (basic socket server)

Run with sufficient privileges to bind to chosen ports

Usage

Clone the repo and run:

python honeypot.py --ports 2222,8080

--- 

## Options:

--ports : Comma-separated list of ports to listen on

--log-dir : Directory for logs (default: logs/)

--max-bytes : Max bytes to capture per connection (default: 1024)

--retain-days N : Retention period for logs

--compress-old : Compression of old logs

---

## Example Runs

SSH Test (Port 2222)  
`ssh localhost -p 2222`  

Resulting log entry (.jsonl format):

`{
  "ts": "2025-09-01T22:20:41Z",
  "event": "connection",
  "local_port": 2222,
  "remote_ip": "127.0.0.1",
  "remote_port": 35312,
  "bytes_captured": 0,
  "payload_preview_hex": ""
}`

HTTP Test (Port 8080)  
`curl http://127.0.0.1:8080/`  

Resulting log entry:

`{
  "ts": "2025-09-01T22:20:41Z",
  "event": "connection",
  "local_port": 8080,
  "remote_ip": "127.0.0.1",
  "remote_port": 35325,
  "bytes_captured": 86,
  "payload_preview_hex": "47 45 54 20 2f 61 6e 79 74 68 69 6e 67 20 48 54 54 50 2f 31 2e 31 ..."
}`

This hex decodes to a standard HTTP GET request.

---

## Disclaimer

This project is for educational and research purposes only.
Use responsibly and only on systems you have authorization to monitor.
