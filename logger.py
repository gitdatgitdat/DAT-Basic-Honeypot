from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone
import json
import socket
from typing import Optional, Dict

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _ascii_preview(b: bytes, max_len: int = 160) -> str:
    # printable ASCII; non-printable as '.'
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in b[:max_len])
    if len(b) > max_len:
        s += "…"
    return s

def _hex_preview(b: bytes, max_len: int = 64) -> str:
    h = " ".join(f"{c:02X}" for c in b[:max_len])
    if len(b) > max_len:
        h += " …"
    return h

@dataclass
class DualLogger:
    log_dir: Path
    jsonl_file: Path = field(init=False)
    text_file: Path = field(init=False)

    def __post_init__(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        self.jsonl_file = self.log_dir / f"{stamp}.jsonl"
        self.text_file  = self.log_dir / f"{stamp}.log"

    def connection(
        self,
        *,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        payload: Optional[bytes] = None,
        note: Optional[str] = None,
        extra: Optional[Dict] = None,
    ) -> None:
        ts = _utc_now()
        payload = payload or b""

        record = {
            "ts": ts,
            "event": "connection",
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "bytes_captured": len(payload),
            "payload_preview_hex": _hex_preview(payload),
            "payload_preview_ascii": _ascii_preview(payload),
        }
        if note:
            record["note"] = note
        if extra:
            record.update(extra)

        # JSONL for the machines
        with self.jsonl_file.open("a", encoding="utf-8") as jf:
            jf.write(json.dumps(record, ensure_ascii=False) + "\n")

        # Make it pretty for the humans
        pretty = (
            f"[{ts}] conn {remote_ip}:{remote_port} -> {local_port} "
            f"bytes={len(payload)}"
        )
        if note:
            pretty += f" note={note}"
        tail = ""
        if payload:
            tail = (
                f"\n  ascii: \"{record['payload_preview_ascii']}\""
                f"\n  hex  : {record['payload_preview_hex']}"
            )
        with self.text_file.open("a", encoding="utf-8") as tf:
            tf.write(pretty + tail + "\n")

@dataclass
class Summary:
    by_port: Dict[int, int] = field(default_factory=dict)
    by_ip: Dict[str, int]   = field(default_factory=dict)
    total: int = 0

    def add(self, local_port: int, remote_ip: str) -> None:
        self.total += 1
        self.by_port[local_port] = self.by_port.get(local_port, 0) + 1
        self.by_ip[remote_ip]   = self.by_ip.get(remote_ip, 0) + 1

    def render(self, top_n: int = 10) -> str:
        def top(d: Dict, n: int):
            return ", ".join(f"{k}:{v}" for k, v in sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]) or "(none)"
        return (
            "\n=== Honeypot Summary ===\n"
            f"Total connections: {self.total}\n"
            f"Top ports: {top(self.by_port, top_n)}\n"
            f"Top IPs  : {top(self.by_ip, top_n)}\n"
            "========================\n"
        )