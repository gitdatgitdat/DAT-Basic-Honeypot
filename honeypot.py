import argparse
import socket
import socketserver
import threading
from datetime import datetime, timezone
from pathlib import Path
from logger import DualLogger, Summary

# Simple banners per-port (can be customized)
DEFAULT_BANNERS = {
    22:    b"SSH-2.0-OpenSSH_8.9\r\n",
    2222:  b"SSH-2.0-OpenSSH_8.9\r\n",
    23:    b"\r\nlogin: ",
    80:    b"HTTP/1.1 400 Bad Request\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n",
    8080:  b"HTTP/1.1 400 Bad Request\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n",
    445:   b"\x00",  # just something to keep the socket open briefly
}

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

def hexdump(b: bytes, max_bytes: int = 256) -> str:
    b = b[:max_bytes]
    return " ".join(f"{x:02x}" for x in b)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def run_server_on_port(port: int, logger: DualLogger, summary: Summary,
                       capture_bytes: int, banners: dict[int, bytes],
                       timeout_sec: float):
    class HPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            client_sock: socket.socket = self.request
            ip, rport = self.client_address
            local_port = port

            # Optional banner
            banner = banners.get(local_port)
            if banner:
                try:
                    client_sock.sendall(banner)
                except Exception:
                    pass

            # Capture a little payload
            data = b""
            try:
                client_sock.settimeout(timeout_sec)
                chunk = client_sock.recv(capture_bytes)
                if chunk:
                    data = chunk
            except Exception:
                pass
            finally:
                try:
                    client_sock.close()
                except Exception:
                    pass

            logger.connection(
                local_port=local_port,
                remote_ip=ip,
                remote_port=rport,
                payload=data,
            )
            # update summary
            summary.add(local_port, ip)

    srv = ThreadedTCPServer(("0.0.0.0", port), HPHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t

def parse_ports(s: str) -> list[int]:
    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return sorted(out)

def main():
    ap = argparse.ArgumentParser(description="DAT Mini Honeypot (TCP)")
    ap.add_argument("--ports", default="2222,8080",
                    help="Comma/range list of TCP ports to bind (default: 2222,8080). Low ports may require admin.")
    ap.add_argument("--log-dir", default="logs", help="Directory for daily logs (default: logs).")
    ap.add_argument("--log-format", choices=["jsonl", "txt"], default="jsonl", help="Log format (default: jsonl).")
    ap.add_argument("--capture-bytes", type=int, default=512, help="Max bytes to capture per connection (default: 512).")
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket timeout seconds (default: 10).")
    ap.add_argument("--no-banners", action="store_true", help="Do not send service banners.")
    args = ap.parse_args()
    
    log_dir = Path(getattr(args, "log_dir", "logs"))
    logger = DualLogger(log_dir=log_dir)
    summary = Summary()

    ports = parse_ports(args.ports)
    if not ports:
        print("[ERROR] No ports to listen on.")
        return

    banners = {} if args.no_banners else DEFAULT_BANNERS

    servers = []
    for p in ports:
        try:
            srv, thread = run_server_on_port(p, logger, summary, args.capture_bytes, banners, args.timeout)
            servers.append(srv)
            print(f"[*] Listening on 0.0.0.0:{p}")
        except Exception as e:
            print(f"[WARN] Failed to bind port {p}: {e}")

    if not servers:
        print("[ERROR] No ports bound. Exiting.")
        return

    print("[*] Honeypot running. Ctrl+C to stop.")
    try:
        while True:
            threading.Event().wait(1.0)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
    finally:
        for srv in servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        print(summary.render())
        print("[*] Goodbye.")

if __name__ == "__main__":
    main()