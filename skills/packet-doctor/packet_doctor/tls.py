"""Passive TLS record/handshake inspection and X.509 validity extraction.

No decryption or certificate path validation is implied by passive inspection.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import ssl

from .stream import provenance


def tlv(data, offset=0):
    if offset + 2 > len(data):
        raise ValueError("Truncated DER")
    tag, length = data[offset], data[offset + 1]
    offset += 2
    if length & 128:
        count = length & 127
        if not 1 <= count <= 4 or offset + count > len(data):
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise ValueError("Truncated DER value")
    return tag, data[offset:offset + length], offset + length


def common_name(name):
    """Return the CN of a DER Name, or None."""
    try:
        pos = 0
        while pos < len(name):
            _, rdn, pos = tlv(name, pos)
            _, attribute, _ = tlv(rdn)
            tag, oid, after = tlv(attribute)
            if tag == 0x06 and oid == b"\x55\x04\x03":
                return tlv(attribute, after)[1].decode("utf-8", "replace")
    except ValueError:
        pass
    return None


def subject_alt_names(tbs, pos):
    """Walk extensions after subject/SPKI. A damaged extension yields no names."""
    names = []
    try:
        while pos < len(tbs):
            tag, value, pos = tlv(tbs, pos)
            if tag != 0xa3:
                continue
            _, extensions, _ = tlv(value)
            offset = 0
            while offset < len(extensions):
                _, extension, offset = tlv(extensions, offset)
                _, oid, after = tlv(extension)
                if oid != b"\x55\x1d\x11":
                    continue
                tag, body, after = tlv(extension, after)
                if tag == 0x01:
                    tag, body, after = tlv(extension, after)
                _, general, _ = tlv(body)
                inner = 0
                while inner < len(general):
                    kind, item, inner = tlv(general, inner)
                    if kind == 0x82:
                        names.append(item.decode("ascii", "replace").lower())
                    elif kind == 0x87 and len(item) in (4, 16):
                        names.append(str(ipaddress.ip_address(item)))
    except ValueError:
        pass
    return names


def certificate_identity(tbs, pos, issuer):
    try:
        _, subject, after = tlv(tbs, pos)
        _, _, after = tlv(tbs, after)
    except ValueError:
        return {"subject_cn": None, "issuer_cn": common_name(issuer), "san": [], "self_issued": False}
    return {"subject_cn": common_name(subject), "issuer_cn": common_name(issuer),
            "san": subject_alt_names(tbs, after), "self_issued": subject == issuer}


def name_matches(host, certificate):
    """Compare a requested name to SAN (else CN), allowing one left-most wildcard label."""
    host = host.lower().rstrip(".")
    names = certificate.get("san") or [(certificate.get("subject_cn") or "").lower()]
    for name in names:
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def certificate_validity(der, at_ns):
    tag, certificate, end = tlv(der)
    if tag != 0x30 or end != len(der):
        raise ValueError("Not an X.509 sequence")
    tag, tbs, _ = tlv(certificate)
    if tag != 0x30:
        raise ValueError("Invalid TBSCertificate")
    pos = 0
    tag, _, after = tlv(tbs, pos)
    if tag == 0xa0:
        pos = after
    issuer = b""
    for expected in (0x02, 0x30, 0x30):  # serial, signature algorithm, issuer
        tag, issuer, pos = tlv(tbs, pos)
        if tag != expected:
            raise ValueError("Invalid TBSCertificate fields")
    tag, validity, pos = tlv(tbs, pos)
    if tag != 0x30:
        raise ValueError("Invalid validity")
    identity = certificate_identity(tbs, pos, issuer)

    def date(offset):
        tag, value, end = tlv(validity, offset)
        text = value.decode("ascii")
        if tag == 0x17 and re.fullmatch(r"\d{12}Z", text):
            year = int(text[:2])
            text = str(1900 + year if year >= 50 else 2000 + year) + text[2:]
        elif tag != 0x18 or not re.fullmatch(r"\d{14}Z", text):
            raise ValueError("Unsupported certificate time format")
        return datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc), end

    before, end = date(0)
    after, end = date(end)
    if end != len(validity) or before > after:
        raise ValueError("Invalid validity interval")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    before_ns = int((before - epoch).total_seconds()) * 1_000_000_000
    after_ns = int((after - epoch).total_seconds()) * 1_000_000_000
    status = "expired" if at_ns > after_ns else "not_yet_valid" if at_ns < before_ns else "within_dates"
    return {"sha256": hashlib.sha256(der).hexdigest(), "not_before": before.isoformat(),
            "not_after": after.isoformat(), "status": status, "evaluated_at_ns": at_ns, **identity,
            "limitations": "有効期間と記載名のみ確認。署名・信頼チェーン・失効状態は未検証"}


def read_certificate(data, at_ns):
    if b"-----BEGIN CERTIFICATE-----" in data:
        match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
        if not match:
            raise ValueError("Invalid PEM certificate")
        data = ssl.PEM_cert_to_DER_cert(match[0].decode("ascii"))
    return certificate_validity(data, at_ns)


def tls_start(raw, role):
    if len(raw) >= 3 and raw[0] in (21, 22) and raw[1] == 3 and raw[2] <= 3:
        return 0
    # Explicit FTP STARTTLS boundary, not an arbitrary scan through binary data.
    boundary = re.search(rb"(?:^|\r\n)AUTH TLS\r\n", raw[:65536], re.I) if role == "client" else re.search(rb"(?:^|\r\n)234 [^\r\n]*\r\n", raw[:65536])
    if boundary:
        offset = boundary.end()
        if raw[offset:offset + 2] in (b"\x16\x03", b"\x15\x03"):
            return offset
    return None


def inspect_tls(raw, spans, role):
    start = tls_start(raw, role)
    if start is None:
        return [], False
    events, pos, handshake = [], start, bytearray()
    handshake_refs, handshake_time = [], 0
    encrypted = False
    while pos + 5 <= len(raw):
        kind, major, minor = raw[pos:pos + 3]
        size = int.from_bytes(raw[pos + 3:pos + 5], "big")
        if major != 3 or minor > 3 or kind not in (20, 21, 22, 23) or size > 18432:
            break
        end = pos + 5 + size
        if end > len(raw):
            break
        body = raw[pos + 5:end]
        refs, ns = provenance(spans, pos, end)
        if kind == 20:
            encrypted = True  # TLS 1.2 CCS, or TLS 1.3 compatibility CCS; both conservative.
        elif kind == 23:
            events.append({"kind": "encrypted", "evidence_ids": refs, "time_ns": ns})
        elif kind == 21 and not encrypted and size == 2:
            events.append({"kind": "alert", "level": body[0], "description": body[1], "evidence_ids": refs, "time_ns": ns})
        elif kind == 22 and not encrypted:
            handshake.extend(body)
            handshake_refs.extend(r for r in refs if r not in handshake_refs)
            handshake_time = max(handshake_time, ns)
            while len(handshake) >= 4:
                length = int.from_bytes(handshake[1:4], "big")
                if length > 1_000_000 or len(handshake) < length + 4:
                    break
                hkind, message = handshake[0], bytes(handshake[4:length + 4])
                event = {"kind": {1: "client_hello", 2: "server_hello", 11: "certificate"}.get(hkind, "handshake"),
                         "time_ns": handshake_time, "evidence_ids": handshake_refs[:], "role": role}
                if hkind == 1:
                    event.update(client_hello_extensions(message))
                if hkind == 2:
                    event["tls13"] = server_hello_tls13(message)
                if hkind == 11:
                    event["certificates"] = []
                    if len(message) >= 3 and int.from_bytes(message[:3], "big") == len(message) - 3:
                        cpos = 3
                        while cpos + 3 <= len(message):
                            clen = int.from_bytes(message[cpos:cpos + 3], "big")
                            cpos += 3
                            if clen == 0 or cpos + clen > len(message):
                                event["parse_warning"] = "証明書リストが不完全です"
                                break
                            try:
                                event["certificates"].append(certificate_validity(message[cpos:cpos + clen], handshake_time))
                            except (ValueError, UnicodeError):
                                event["parse_warning"] = "証明書の有効期間を読み取れませんでした"
                            cpos += clen
                    else:
                        event["parse_warning"] = "対応する平文TLS証明書形式ではありません"
                events.append(event)
                del handshake[:length + 4]
                # Keep refs when multiple handshake messages share a record.
                if not handshake:
                    handshake_refs, handshake_time = [], 0
        pos = end
    return events, True


def client_hello_extensions(message):
    """Return SNI and ALPN from a plaintext ClientHello when present."""
    result = {}
    try:
        pos = 34
        pos += 1 + message[pos]
        pos += 2 + int.from_bytes(message[pos:pos + 2], "big")
        pos += 1 + message[pos]
        end = min(len(message), pos + 2 + int.from_bytes(message[pos:pos + 2], "big"))
        pos += 2
        while pos + 4 <= end:
            kind, size = int.from_bytes(message[pos:pos + 2], "big"), int.from_bytes(message[pos + 2:pos + 4], "big")
            body, pos = message[pos + 4:pos + 4 + size], pos + 4 + size
            if kind == 0 and len(body) > 5 and body[2] == 0:
                result["sni"] = body[5:5 + int.from_bytes(body[3:5], "big")].decode("ascii", "replace").lower()
            elif kind == 16 and len(body) > 3:
                result["alpn"] = body[3:3 + body[2]].decode("ascii", "replace")
    except IndexError:
        pass
    return result


def server_hello_tls13(message):
    if len(message) < 38:
        return False
    offset = 35 + message[34] + 3
    if offset + 2 > len(message):
        return False
    size = int.from_bytes(message[offset:offset + 2], "big")
    offset += 2
    end = min(len(message), offset + size)
    while offset + 4 <= end:
        kind = int.from_bytes(message[offset:offset + 2], "big")
        size = int.from_bytes(message[offset + 2:offset + 4], "big")
        offset += 4
        if offset + size > end:
            break
        if kind == 43 and message[offset:offset + size] == b"\x03\x04":
            return True
        offset += size
    return False
