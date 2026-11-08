"""Builtin frame decoding: link layer, IPv4/IPv6, TCP, UDP/DNS, ICMP and ARP."""
import ipaddress
import struct

from .models import Packet

ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP = 0x0800, 0x86DD, 0x0806
AF_INET6_VALUES = (10, 24, 28, 30)


def dns_name(data, start):
    labels, visited, pos, after = [], set(), start, None
    for _ in range(128):
        if pos >= len(data) or pos in visited:
            raise ValueError("DNS name is truncated or cyclic")
        visited.add(pos)
        size = data[pos]
        if size & 0xc0 == 0xc0:
            if pos + 1 >= len(data):
                raise ValueError("DNS pointer truncated")
            if after is None:
                after = pos + 2
            pos = ((size & 63) << 8) | data[pos + 1]
            continue
        if size & 0xc0:
            raise ValueError("Unsupported DNS label")
        pos += 1
        if size == 0:
            return ".".join(labels), after if after is not None else pos
        if pos + size > len(data):
            raise ValueError("DNS label truncated")
        labels.append(data[pos:pos + size].decode("ascii", "backslashreplace"))
        pos += size
    raise ValueError("DNS name too deep")


def dns_answers(data, pos, count):
    """Return A/AAAA addresses. A damaged answer section ends the walk, not the event."""
    found = []
    try:
        for _ in range(min(count, 64)):
            _, pos = dns_name(data, pos)
            if pos + 10 > len(data):
                break
            kind, _, _, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if pos + size > len(data):
                break
            if (kind, size) in ((1, 4), (28, 16)):
                found.append(str(ipaddress.ip_address(data[pos:pos + size])))
            pos += size
    except ValueError:
        pass
    return found


def decode_dns(data):
    if len(data) < 12:
        raise ValueError("DNS header truncated")
    ident, flags, questions, answers, _, _ = struct.unpack_from("!6H", data)
    if questions != 1 or (flags >> 11) & 15:
        raise ValueError("Only standard single-question DNS is supported")
    name, pos = dns_name(data, 12)
    if pos + 4 > len(data):
        raise ValueError("DNS question truncated")
    qtype, qclass = struct.unpack_from("!HH", data, pos)
    return {"kind": "dns", "transaction_id": ident, "response": bool(flags & 0x8000),
            "rcode": flags & 15, "name": name.lower(), "qtype": qtype, "qclass": qclass,
            "truncated": bool(flags & 0x200), "answer_count": answers,
            "answers": dns_answers(data, pos + 4, answers)}


def locate_network_layer(data, link, warnings):
    """Return (ethertype, offset) for the supported link types, else None."""
    if link == 1:
        if len(data) < 14:
            warnings.add("短いEthernetフレームを除外しました")
            return None
        ethertype, pos = int.from_bytes(data[12:14], "big"), 14
        while ethertype in (0x8100, 0x88A8):
            if len(data) < pos + 4:
                warnings.add("不完全なVLANヘッダーを除外しました")
                return None
            ethertype = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
        return ethertype, pos
    if link == 113 and len(data) >= 16:  # Linux cooked v1 (tcpdump -i any)
        return int.from_bytes(data[14:16], "big"), 16
    if link == 276 and len(data) >= 20:  # Linux cooked v2
        return int.from_bytes(data[:2], "big"), 20
    if link in (0, 108) and len(data) >= 4:  # BSD/Windows loopback; byte order varies
        family = int.from_bytes(data[:4], "big" if link == 108 else "little")
        if family > 0xffff:
            family = int.from_bytes(data[:4], "big")
        if family == 2:
            return ETHERTYPE_IPV4, 4
        return (ETHERTYPE_IPV6, 4) if family in AF_INET6_VALUES else None
    if link in (12, 14, 101, 228, 229) and data:  # Raw IP
        return (ETHERTYPE_IPV6 if data[0] >> 4 == 6 else ETHERTYPE_IPV4), 0
    if link not in (1, 113, 276, 0, 108, 12, 14, 101, 228, 229):
        warnings.add(f"内蔵解析の非対応リンク種別: {link}。tsharkを利用してください")
    return None


def parse_ip(data, pos, ethertype, warnings):
    """Return the IP header fields and as much payload as the capture holds."""
    packet = data[pos:]
    if ethertype == ETHERTYPE_IPV4:
        if len(packet) < 20:
            warnings.add("不完全なIPv4ヘッダーを除外しました")
            return None
        header, total = (packet[0] & 15) * 4, int.from_bytes(packet[2:4], "big")
        if packet[0] >> 4 != 4 or header < 20 or total < header or len(packet) < header:
            warnings.add("不正なIPv4パケットを除外しました")
            return None
        if int.from_bytes(packet[6:8], "big") & 0x3fff:
            warnings.add("断片化IPv4は内蔵解析から除外しました")
            return None
        return {"version": 4, "src": str(ipaddress.ip_address(packet[12:16])),
                "dst": str(ipaddress.ip_address(packet[16:20])), "proto": packet[9], "ttl": packet[8],
                "ip_id": int.from_bytes(packet[4:6], "big"), "payload": packet[header:total],
                "payload_total": total - header}
    if ethertype == ETHERTYPE_IPV6:
        if len(packet) < 40 or packet[0] >> 4 != 6:
            warnings.add("不完全なIPv6ヘッダーを除外しました")
            return None
        proto, size = packet[6], int.from_bytes(packet[4:6], "big")
        if proto not in (1, 6, 17, 58):
            if proto in (0, 43, 44, 50, 51, 60):
                warnings.add("拡張ヘッダー付きIPv6は内蔵解析から除外しました。tsharkを利用してください")
            return None
        return {"version": 6, "src": str(ipaddress.ip_address(packet[8:24])),
                "dst": str(ipaddress.ip_address(packet[24:40])), "proto": proto, "ttl": packet[7],
                "ip_id": None, "payload": packet[40:40 + size], "payload_total": size}
    return None


def tcp_options(data):
    """Parse handshake options; malformed lists stop parsing without failing the frame."""
    result, pos = {}, 0
    while pos < len(data):
        kind = data[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 1 >= len(data) or data[pos + 1] < 2:
            break
        size = data[pos + 1]
        value = data[pos + 2:pos + size]
        if kind == 2 and len(value) == 2:
            result["mss"] = int.from_bytes(value, "big")
        elif kind == 3 and len(value) == 1:
            result["wscale"] = value[0]
        elif kind == 4:
            result["sack_permitted"] = True
        pos += size
    return result


def decode_tcp(ip, capture_id, frame, ns, interface, warnings):
    tcp = ip["payload"]
    if len(tcp) < 20:
        warnings.add("不完全なTCPヘッダーを除外しました")
        return None
    header = (tcp[12] >> 4) * 4
    if header < 20 or header > ip["payload_total"]:
        warnings.add("TCPヘッダー長が不正です")
        return None
    if header > len(tcp):
        warnings.add("TCPオプションまで保存されていないパケットを除外しました")
        return None
    sport, dport, seq, ack = struct.unpack_from("!HHII", tcp)
    payload, wire_length = tcp[header:], ip["payload_total"] - header
    if len(payload) != wire_length:
        warnings.add("切り詰められたパケットはヘッダーのみ解析し、ペイロード解析の対象外にしました")
    options = tcp_options(tcp[20:header]) if tcp[13] & 2 else {}
    return Packet(capture_id, frame, ns, ip["src"], ip["dst"], sport, dport, seq, ack, tcp[13],
                  int.from_bytes(tcp[14:16], "big"), payload, interface, ttl=ip["ttl"], ip_id=ip["ip_id"],
                  tcp_len=None if len(payload) == wire_length else wire_length, mss=options.get("mss"),
                  wscale=options.get("wscale"), sack_permitted=options.get("sack_permitted", False))


def base_event(capture_id, frame, ns, interface, src, dst):
    return {"capture_id": capture_id, "frame": frame, "time_ns": ns, "src": src, "dst": dst, "sport": None,
            "dport": None, "interface": interface, "id": f"{capture_id}:frame:{frame}",
            "filter": f"frame.number == {frame}"}


def decode_arp(data, pos, event_args):
    arp = data[pos:]
    if len(arp) < 8 or int.from_bytes(arp[2:4], "big") != ETHERTYPE_IPV4 or arp[5] != 4:
        return None
    hardware, opcode = arp[4], int.from_bytes(arp[6:8], "big")
    if len(arp) < 16 + 2 * hardware:
        return None
    sender = str(ipaddress.ip_address(arp[8 + hardware:12 + hardware]))
    target = str(ipaddress.ip_address(arp[12 + 2 * hardware:16 + 2 * hardware]))
    event = base_event(*event_args, sender, target)
    event.update(kind="arp", opcode=opcode, sender_mac=arp[8:8 + hardware].hex(":"))
    return event


def decode_quoted(event, quoted):
    if len(quoted) >= 20 and quoted[0] >> 4 == 4:
        event["quoted_src"] = str(ipaddress.ip_address(quoted[12:16]))
        event["quoted_dst"] = str(ipaddress.ip_address(quoted[16:20]))
        header, proto = (quoted[0] & 15) * 4, quoted[9]
    elif len(quoted) >= 40 and quoted[0] >> 4 == 6:
        event["quoted_src"] = str(ipaddress.ip_address(quoted[8:24]))
        event["quoted_dst"] = str(ipaddress.ip_address(quoted[24:40]))
        header, proto = 40, quoted[6]
    else:
        return
    if header >= 20 and len(quoted) >= header + 4 and proto in (6, 17):
        event["quoted_sport"], event["quoted_dport"] = struct.unpack_from("!HH", quoted, header)


def decode_frame(data, link, capture_id, frame, ns, interface, warnings):
    """Return (tcp_packet_or_None, network_event_or_None) for one captured frame."""
    located = locate_network_layer(data, link, warnings)
    if located is None:
        return None, None
    ethertype, pos = located
    event_args = (capture_id, frame, ns, interface)
    if ethertype == ETHERTYPE_ARP:
        return None, decode_arp(data, pos, event_args)
    if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        return None, None
    ip = parse_ip(data, pos, ethertype, warnings)
    if ip is None:
        return None, None
    if ip["proto"] == 6:
        return decode_tcp(ip, capture_id, frame, ns, interface, warnings), None
    payload, event = ip["payload"], base_event(*event_args, ip["src"], ip["dst"])
    if ip["proto"] == 17 and len(payload) >= 8:
        sport, dport, length = struct.unpack_from("!HHH", payload)
        if 53 not in (sport, dport):
            return None, None
        if length < 8 or length > len(payload):
            warnings.add("DNSのUDPデータが不完全です")
            return None, None
        try:
            event.update(decode_dns(payload[8:length]), sport=sport, dport=dport)
            return None, event
        except ValueError:
            warnings.add("不完全または非対応のDNSメッセージがあり、判定から除外しました")
            return None, None
    if ip["proto"] == 1 and len(payload) >= 8 and payload[0] in (3, 11):
        event.update(kind="icmp", icmp_version=4, icmp_type=payload[0], icmp_code=payload[1])
        decode_quoted(event, payload[8:])
        return None, event
    if ip["proto"] == 58 and len(payload) >= 8 and payload[0] in (1, 2, 3):
        event.update(kind="icmp", icmp_version=6, icmp_type=payload[0], icmp_code=payload[1])
        decode_quoted(event, payload[8:])
        return None, event
    return None, None
