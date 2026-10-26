"""Logging network sink for the SCC egress test (ADR 0019, decision 2).

The sink is the only peer of the scan container on an internal Docker network.
It runs with the standard library only:

- a DNS server on UDP and TCP port 53 that answers every A query with the sink's
  own address and logs each query;
- TCP listeners on the usual web ports that accept, log and reset each
  connection;
- a packet sniffer (``AF_PACKET``) that logs every IPv4 TCP SYN, UDP datagram and
  ICMP packet addressed to the sink, so a connection to any other port, which the
  kernel resets, is logged too.

Every event is one JSON line in the log file. The test reads the file; the sink
never decides anything itself.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path

DNS_PORT = 53
WEB_PORTS = (80, 443, 8080, 8443)
ETH_P_ALL = 0x0003
ETHERNET_HEADER = 14
IPV4 = 0x0800
PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp"}
TCP_SYN = 0x02
TCP_ACK = 0x10
BUFFER = 65535
LINGER_RESET = struct.pack("ii", 1, 0)
DNS_HEADER = 12
DNS_TTL = 1


class EventLog:
    """Thread-safe JSON lines writer."""

    def __init__(self, path: Path) -> None:
        """Open the log for appending."""
        self._lock = threading.Lock()
        self._handle = path.open("a", encoding="utf-8")

    def write(self, **event: object) -> None:
        """Append one event with a timestamp."""
        event["time"] = time.time()
        with self._lock:
            self._handle.write(json.dumps(event, sort_keys=True) + "\n")
            self._handle.flush()


def question_name(packet: bytes) -> tuple[str, int]:
    """Return the first question name of a DNS message and the offset after it."""
    labels: list[str] = []
    offset = DNS_HEADER
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset + 4


def dns_answer(query: bytes, address: str) -> bytes:
    """Answer a DNS query with one A record pointing at ``address``."""
    _, end = question_name(query)
    header = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", DNS_TTL, 4)
    return header + query[DNS_HEADER:end] + answer + socket.inet_aton(address)


def serve_dns_udp(log: EventLog, address: str) -> None:
    """Answer and log DNS queries over UDP."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", DNS_PORT))
    while True:
        query, peer = server.recvfrom(BUFFER)
        name = question_name(query)[0]
        log.write(kind="dns", transport="udp", name=name, source=peer[0])
        server.sendto(dns_answer(query, address), peer)


def serve_tcp(log: EventLog, port: int) -> None:
    """Accept, log and reset every TCP connection on ``port``."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(64)
    while True:
        connection, peer = server.accept()
        log.write(kind="connection", port=port, source=peer[0])
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER_RESET)
        connection.close()


def classify(frame: bytes, address: bytes) -> dict[str, object] | None:
    """Return the event for an IPv4 frame addressed to the sink, or ``None``."""
    if len(frame) < ETHERNET_HEADER + 20 or struct.unpack("!H", frame[12:14])[0] != IPV4:
        return None
    packet = frame[ETHERNET_HEADER:]
    if packet[16:20] != address or packet[12:16] == address:
        return None
    protocol = PROTOCOLS.get(packet[9], str(packet[9]))
    header = (packet[0] & 0x0F) * 4
    event: dict[str, object] = {
        "kind": "packet",
        "protocol": protocol,
        "source": socket.inet_ntoa(packet[12:16]),
    }
    if protocol in {"tcp", "udp"} and len(packet) >= header + 4:
        event["port"] = struct.unpack("!H", packet[header + 2 : header + 4])[0]
    if protocol == "tcp" and len(packet) >= header + 14:
        flags = packet[header + 13]
        if not flags & TCP_SYN or flags & TCP_ACK:
            return None
    return event


def sniff(log: EventLog, address: str) -> None:
    """Log every TCP SYN, UDP datagram and ICMP packet sent to the sink."""
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    own = socket.inet_aton(address)
    while True:
        event = classify(raw.recv(BUFFER), own)
        if event is not None:
            log.write(**event)


def main(argv: list[str]) -> int:
    """Start every listener and keep running."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument("--log", type=Path, required=True)
    arguments = parser.parse_args(argv)
    log = EventLog(arguments.log)
    address: str = arguments.address
    threads = [
        threading.Thread(target=serve_dns_udp, args=(log, address), daemon=True),
        threading.Thread(target=serve_tcp, args=(log, DNS_PORT), daemon=True),
        threading.Thread(target=sniff, args=(log, address), daemon=True),
    ]
    threads.extend(
        threading.Thread(target=serve_tcp, args=(log, port), daemon=True) for port in WEB_PORTS
    )
    for thread in threads:
        thread.start()
    log.write(kind="ready")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
