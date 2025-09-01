import argparse
import json
import socket
import socketserver
import threading
from datetime import datetime, timezone
from pathlib import Path

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

class DailyLogger:
    def __init__(self, log_dir: Path, kind: str = "jsonl"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.kind = kind
        self._lock = threading.Lock()

    def _path(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        ext = "jsonl" if self.kind == "jsonl" else "log"
        return self.log_dir / f"{stamp}.{ext}"

    def write_event(self, obj: dict):
        line = json.dumps(obj, ensure_ascii=False) if self.kind == "jsonl" else str(obj)
        with self._lock:
            with self._path().open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

def hexdump(b: bytes, max_bytes: int = 256) -> str:
    b = b[:max_bytes]
    return " ".join(f"{x:02x}" for x in b)

class HoneypotHandler(socketserver.BaseRequestHandler):
    # class-level config injected at server creation
    logger: DailyLogger = None
    capture_bytes: int = 512
    banners: dict = {}
    timeout: float = 10.0

    def handle(self):
        self.request.settimeout(self.timeout)
        peer_ip, peer_port = self.client_address
        local_port = self.server.server_address[1]

        # Optional banner (fake service feel)
        banner = self.banners.get(local_port)
        if banner:
            try:
                self.request.sendall(banner)
            except Exception:
                pass

        # Read a small amount of data
        received = b""
        try:
            chunk = self.request.recv(self.capture_bytes)
            if chunk:
                received = chunk
        except Exception:
            pass  # timeouts or resets are fine

        event = {
            "ts": now_utc(),
            "event": "connection",
            "local_port": local_port,
            "remote_ip": peer_ip,
            "remote_port": peer_port,
            "bytes_captured": len(received),
            "payload_preview_hex": hexdump(received, 64),  # keep small in logs
        }
        self.logger.write_event(event)

        # Optionally keep the socket open a bit to look “alive”
        try:
            self.request.settimeout(0.5)
            _ = self.request.recv(1)
        except Exception:
            pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def run_server_on_port(port: int, logger: DailyLogger, capture_bytes: int, banners: dict, timeout: float):
    handler = type(
        "CfgHandler",
        (HoneypotHandler,),
        {
            "logger": logger,
            "capture_bytes": capture_bytes,
            "banners": banners,
            "timeout": timeout,
        },
    )
    srv = ThreadedTCPServer(("0.0.0.0", port), handler)
    t = threading.Thread(target=srv.serve_forever, name=f"hp-{port}", daemon=True)
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

    ports = parse_ports(args.ports)
    if not ports:
        print("[ERROR] No ports to listen on.")
        return

    banners = {} if args.no_banners else DEFAULT_BANNERS
    logger = DailyLogger(Path(args.log_dir), args.log_format)

    servers = []
    for p in ports:
        try:
            srv, thread = run_server_on_port(p, logger, args.capture_bytes, banners, args.timeout)
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
        print("[*] Goodbye.")

if __name__ == "__main__":
    main()