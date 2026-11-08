"""Generate real, synthetic Ethernet/IPv4/TCP pcap fixtures. No network I/O."""
from pathlib import Path
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(src, dst, sport, dport, seq, ack, flags, payload=b"", window=8192):
    source, destination = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + tcp


def write_pcap(path, records):
    with Path(path).open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ns, data in records:
            seconds, remainder = divmod(ns, 1_000_000_000)
            stream.write(struct.pack("<IIII", seconds, remainder // 1000, len(data), len(data)))
            stream.write(data)


def write_pcapng(path, records):
    def block(kind, data):
        data += b"\0" * (-len(data) % 4)
        size = len(data) + 12
        return struct.pack("<II", kind, size) + data + struct.pack("<I", size)
    with Path(path).open("wb") as stream:
        stream.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        stream.write(block(1, struct.pack("<HHI", 1, 0, 65535)))
        for ns, data in records:
            timestamp = ns // 1000
            stream.write(block(6, struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xffffffff, len(data), len(data)) + data))


def demo_records(gap_ms=5000, response_ms=620):
    result = []
    origin = 1_700_000_000_000_000_000

    def add(ms, reverse, sport, seq, ack, flags, payload=b""):
        args = ("192.0.2.20", "192.0.2.10", 5000, sport) if reverse else ("192.0.2.10", "192.0.2.20", sport, 5000)
        result.append((origin + ms * 1_000_000, frame(*args, seq, ack, flags, payload)))

    add(0, False, 42000, 100, 0, 2)
    add(10, True, 42000, 900, 101, 18)
    add(20, False, 42000, 101, 901, 16)
    add(1000, True, 42000, 901, 101, 20)
    start = 1000 + gap_ms
    add(start, False, 42001, 200, 0, 2)
    add(start + 10, True, 42001, 1000, 201, 18)
    add(start + 20, False, 42001, 201, 1001, 16)
    # Split a request across two TCP packets to exercise message reconstruction.
    add(start + 30, False, 42001, 201, 1001, 24, b"\x00\x06\x01")
    add(start + 31, False, 42001, 204, 1001, 24, b"\x07\xaa\xbb")
    add(start + 31 + response_ms, True, 42001, 1001, 207, 24, b"\x00\x06\x81\x07\x00\x01")
    return result


def create_demo(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    for name, records in (("slow", demo_records()), ("normal", demo_records(200, 100))):
        for extension, writer in (("pcap", write_pcap), ("pcapng", write_pcapng)):
            path = directory / f"{name}.{extension}"
            if path.exists():
                raise FileExistsError(f"既存のデモを上書きしません: {path}")
            writer(path, records)
    return {"directory": str(directory), "capture": str(directory / "slow.pcapng"),
            "expected": {"observed_gap_ms": 5000, "handshake_ms": 20, "response_ms": 620}}
