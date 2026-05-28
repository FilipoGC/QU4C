#!/usr/bin/env python3
import binascii
import sys
import time
from typing import Dict, Tuple

import scapy.all as scapy  # type: ignore

CLIENT_IFACE = "eno7"
SERVER_IFACE = "ens1f0np0"

CLIENT_MAC = "ac:1f:6b:67:06:70"
SERVER_MAC = "c4:70:bd:8b:c8:0c"

CLIENT_IP = "13.13.13.49"
SERVER_IP = "13.13.13.50"

UDP_SPORT = 52005
UDP_DPORT = 4433
IP_TTL = 64

CLIENT_CID = "b6549911c4eb2952"
SERVER_CID = "5e1eb1799edb1083"
INITIAL_DCID = "f4e7045522ad8fc0"
QUIC_VERSION = 1

CLIENT_INITIAL_LEN = 1200
CLIENT_HANDSHAKE_LEN = 49
CLIENT_AFTER_INITIAL_WAIT = 1.0
CLIENT_AFTER_HANDSHAKE_WAIT = 0.01
CLIENT_AFTER_FIRST_REQUEST_SLEEP = 30.0

CHACHA_CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def get_data_size() -> int:
    if len(sys.argv) > 1:
        return int(sys.argv[1])
    return 384


def require_iface(iface: str) -> None:
    if iface not in scapy.get_if_list():
        raise SystemExit("Interface '%s' not found. Available interfaces: %s" % (iface, ", ".join(scapy.get_if_list())))


def hx(value: str, expected_bytes: int) -> bytes:
    text = value.replace(":", "").replace(" ", "").strip()
    if len(text) != expected_bytes * 2:
        raise ValueError("Invalid hex value: %s" % value)
    return binascii.unhexlify(text)


def rol(x: int, w: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << w) | (x >> (32 - w))) & 0xFFFFFFFF


def qr(state, a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rol(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rol(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rol(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rol(state[b], 7)


def chacha20_pad(position: int, nonce: bytes) -> bytes:
    keys = [0] * 8
    nonces = [int.from_bytes(nonce[i * 4: i * 4 + 4], "big") for i in range(2)]
    state = [0] * 16
    state[:4] = CHACHA_CONST
    state[4:12] = keys
    state[12] = position
    state[13] = 0
    state[14:] = nonces
    initial = list(state)

    for i in range(1, 21):
        if i % 2:
            qr(state, 0, 4, 8, 12)
            qr(state, 1, 5, 9, 13)
            qr(state, 2, 6, 10, 14)
            qr(state, 3, 7, 11, 15)
        else:
            qr(state, 0, 5, 10, 15)
            qr(state, 1, 6, 11, 12)
            qr(state, 2, 7, 8, 13)
            qr(state, 3, 4, 9, 14)

    out = bytearray()
    for i in range(16):
        out.extend(((state[i] + initial[i]) & 0xFFFFFFFF).to_bytes(4, "big"))
    return bytes(out)


def raw_chacha_len(data_size: int) -> int:
    return 13 + data_size


def build_raw_chacha(data_size: int, eg_port: int = 50, nonce_hex: str = "0000000000000000") -> bytes:
    nonce = hx(nonce_hex, 8)
    chacha_pre = bytes([0x80, 0x00, 0x00]) + int(eg_port).to_bytes(2, "big")
    data = b"".join(chacha20_pad(i, nonce) for i in range(data_size // 64))
    return chacha_pre + nonce + data


def quic_varint_encode(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (0x4000 | value).to_bytes(2, "big")
    if value < 0x40000000:
        return (0x80000000 | value).to_bytes(4, "big")
    return (0xC000000000000000 | value).to_bytes(8, "big")


def quic_varint_decode(buf: bytes, offset: int) -> Tuple[int, int]:
    first = buf[offset]
    length = 1 << (first >> 6)
    raw = int.from_bytes(buf[offset:offset + length], "big")
    mask = (1 << (8 * length - 2)) - 1
    return raw & mask, offset + length


def build_long_packet(total_len: int, packet_type: int, dcid_hex: str, scid_hex: str, pn: int) -> bytes:
    dcid = hx(dcid_hex, 8)
    scid = hx(scid_hex, 8)
    pn_len = 2
    first = 0xC0 | ((packet_type & 0x03) << 4) | (pn_len - 1)

    base = bytearray([first])
    base.extend(QUIC_VERSION.to_bytes(4, "big"))
    base.append(len(dcid))
    base.extend(dcid)
    base.append(len(scid))
    base.extend(scid)

    if packet_type == 0:
        base.extend(quic_varint_encode(0))

    for encoded_len_size in (1, 2, 4, 8):
        payload_len = total_len - len(base) - encoded_len_size - pn_len
        if payload_len < 0:
            continue
        encoded = quic_varint_encode(pn_len + payload_len)
        if len(encoded) == encoded_len_size:
            return bytes(base) + encoded + pn.to_bytes(pn_len, "big") + (b"\x00" * payload_len)

    raise ValueError("Cannot build long-header packet with length %d" % total_len)


def build_short_packet(dcid_hex: str, pn: int, payload: bytes, spin: int = 0) -> bytes:
    first = 0x40 | ((1 if spin else 0) << 5)
    return bytes([first]) + hx(dcid_hex, 8) + bytes([pn & 0xFF]) + payload


def build_l2_packet(quic_payload: bytes):
    pkt = (
        scapy.Ether(src=CLIENT_MAC, dst=SERVER_MAC, type=0x0800)
        / scapy.IP(src=CLIENT_IP, dst=SERVER_IP, ttl=IP_TTL, flags="DF")
        / scapy.UDP(sport=UDP_SPORT, dport=UDP_DPORT, chksum=0)
        / scapy.Raw(quic_payload)
    )
    pkt[scapy.IP].len = None
    pkt[scapy.IP].chksum = None
    pkt[scapy.UDP].len = None
    pkt[scapy.UDP].chksum = 0
    return pkt


def parse_quic(payload: bytes) -> Dict:
    first = payload[0]
    info: Dict = {"quic_len": len(payload), "header_form": 1 if (first & 0x80) else 0}

    if info["header_form"]:
        packet_type = (first >> 4) & 0x03
        pn_len = (first & 0x03) + 1
        offset = 5

        dcil = payload[offset]
        offset += 1
        dcid = payload[offset:offset + dcil].hex()
        offset += dcil

        scil = payload[offset]
        offset += 1
        scid = payload[offset:offset + scil].hex()
        offset += scil

        if packet_type == 0:
            token_len, offset = quic_varint_decode(payload, offset)
            offset += token_len

        _, offset = quic_varint_decode(payload, offset)
        pn = int.from_bytes(payload[offset:offset + pn_len], "big")

        info.update({"packet_type": packet_type, "dcid": dcid, "scid": scid, "pn": pn})
        return info

    pn_len = (first & 0x03) + 1
    dcid = payload[1:9].hex()
    pn_offset = 9
    pn = int.from_bytes(payload[pn_offset:pn_offset + pn_len], "big")
    info.update({"dcid": dcid, "pn": pn, "spin": 1 if (first & 0x20) else 0})
    return info


def summary(info: Dict) -> str:
    if info.get("header_form"):
        names = {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}
        return "long/%s len=%s pn=%s dcid=%s scid=%s" % (
            names.get(info.get("packet_type"), "?"),
            info.get("quic_len"),
            info.get("pn"),
            info.get("dcid"),
            info.get("scid"),
        )

    return "short len=%s pn=%s spin=%s dcid=%s" % (
        info.get("quic_len"),
        info.get("pn"),
        info.get("spin"),
        info.get("dcid"),
    )


def send_quic(quic_payload: bytes, label: str) -> None:
    pkt = build_l2_packet(quic_payload)
    print("[SEND] %-22s %s:%s -> %s:%s quic_len=%d" % (
        label, pkt[scapy.IP].src, pkt[scapy.UDP].sport, pkt[scapy.IP].dst, pkt[scapy.UDP].dport, len(quic_payload)
    ))
    scapy.sendp(pkt, iface=CLIENT_IFACE, verbose=False)


def packet_is_from_server(pkt) -> bool:
    return (
        scapy.Ether in pkt and scapy.IP in pkt and scapy.UDP in pkt and scapy.Raw in pkt
        and pkt[scapy.Ether].src.lower() == SERVER_MAC
        and pkt[scapy.IP].src == SERVER_IP
        and int(pkt[scapy.UDP].dport) == UDP_SPORT
    )


def main() -> None:
    data_size = get_data_size()
    require_iface(CLIENT_IFACE)

    print("QU4C auxiliary client")
    print("iface=%s %s/%s -> %s/%s" % (CLIENT_IFACE, CLIENT_IP, CLIENT_MAC, SERVER_IP, SERVER_MAC))
    print("SERVER_CID/DCID=%s" % SERVER_CID)
    print("request_data_size=%d raw_len=%d" % (data_size, raw_chacha_len(data_size)))

    def on_rx(pkt):
        if not packet_is_from_server(pkt):
            return
        try:
            info = parse_quic(bytes(pkt[scapy.Raw]))
            print("[RX] server", summary(info))
        except Exception as exc:
            print("[WARN] server packet parse failed:", exc)

    sniffer = scapy.AsyncSniffer(iface=CLIENT_IFACE, store=False, prn=on_rx, promisc=True)
    sniffer.start()
    time.sleep(0.2)

    try:
        send_quic(build_long_packet(CLIENT_INITIAL_LEN, 0, INITIAL_DCID, CLIENT_CID, 0), "client initial")
        time.sleep(CLIENT_AFTER_INITIAL_WAIT)

        send_quic(build_long_packet(CLIENT_HANDSHAKE_LEN, 2, SERVER_CID, CLIENT_CID, 0), "client handshake")
        time.sleep(CLIENT_AFTER_HANDSHAKE_WAIT)

        request = build_short_packet(SERVER_CID, 0, build_raw_chacha(data_size), spin=1)
        send_quic(request, "client 1-RTT request")

        print("[INFO] client stopped generating requests; PktGen should take over.")
        print("[INFO] waiting %.1fs for ACK/takeover." % CLIENT_AFTER_FIRST_REQUEST_SLEEP)
        time.sleep(CLIENT_AFTER_FIRST_REQUEST_SLEEP)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


main()
