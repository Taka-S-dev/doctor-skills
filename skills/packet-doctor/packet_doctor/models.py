from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
import os
import tempfile


class InvestigationError(Exception):
    def __init__(self, message, code="invalid_input"):
        super().__init__(message)
        self.code = code


@dataclass
class Packet:
    capture_id: str
    frame: int
    time_ns: int
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes = b""
    interface: str = "0"
    ttl: int | None = None
    ip_id: int | None = None
    # Set only when the wire length differs from the captured payload (snaplen).
    tcp_len: int | None = None
    mss: int | None = None
    wscale: int | None = None
    sack_permitted: bool = False
    analysis: tuple = ()
    analyzed: bool = False
    rtt_ns: int | None = None

    @property
    def evidence_id(self):
        return f"{self.capture_id}:frame:{self.frame}"

    @property
    def segment_length(self):
        return len(self.payload) if self.tcp_len is None else self.tcp_len

    def evidence(self):
        data = asdict(self)
        data.pop("payload")
        data.pop("analyzed")
        for key in ("tcp_len", "mss", "wscale", "rtt_ns", "ip_id"):
            if data[key] is None:
                data.pop(key)
        data.pop("sack_permitted")
        data["analysis"] = list(self.analysis)
        if not data["analysis"]:
            data.pop("analysis")
        data["payload_length"] = self.segment_length
        data["captured_payload_length"] = len(self.payload)
        data["id"] = self.evidence_id
        data["filter"] = f"frame.number == {self.frame}"
        return data


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def atomic_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".writing-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
