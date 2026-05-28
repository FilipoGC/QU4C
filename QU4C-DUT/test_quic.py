#!/usr/bin/env python3
import binascii
import sys
import time
import warnings

from typing import Dict, Optional, Tuple

warnings.filterwarnings("ignore", message=".*Unable to import Axes3D.*")
warnings.filterwarnings("ignore", message=".*TripleDES.*")
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
QUIC_VERSION = 1

SERVER_HANDSHAKE_BIG_LEN = 1023
SERVER_HANDSHAKE_SMALL_LEN = 293
SERVER_ACK_LEN = 33

SERVER_HANDSHAKE_GAP = 0.00003
SERVER_ACK_DELAY = 0.002
SNIFF_SLICE = 0.2


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


def raw_chacha_len(data_size: int) -> int:
    return 13 + data_size


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
        scapy.Ether(src=SERVER_MAC, dst=CLIENT_MAC, type=0x0800)
        / scapy.IP(src=SERVER_IP, dst=CLIENT_IP, ttl=IP_TTL, flags="DF")
        / scapy.UDP(sport=UDP_DPORT, dport=UDP_SPORT, chksum=0)
        / scapy.Raw(quic_payload)
    )
    pkt[scapy.IP].len = None
    pkt[scapy.IP].chksum = None
    pkt[scapy.UDP].len = None
    pkt[scapy.UDP].chksum = 0
    return pkt


def parse_raw_chacha(payload: bytes) -> Optional[Dict]:
    if len(payload) < 13:
        return None
    if payload[1] != 0 or payload[2] != 0:
        return None
    data_len = len(payload) - 13
    if data_len <= 0 or (data_len % 64) != 0:
        return None
    return {
        "raw_len": len(payload),
        "data_size": data_len,
        "n_blocks": data_len // 64,
        "eg_port": int.from_bytes(payload[3:5], "big"),
        "nonce": payload[5:13].hex(),
        "encrypt": bool(payload[0] & 0x80),
    }


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
    app_payload = payload[pn_offset + pn_len:]
    info.update({
        "dcid": dcid,
        "pn": pn,
        "spin": 1 if (first & 0x20) else 0,
        "payload_len": len(app_payload),
        "raw_chacha": parse_raw_chacha(app_payload),
    })
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

    raw = info.get("raw_chacha")
    extra = ""
    if raw:
        extra = " raw=%sB blocks=%s eg_port=%s nonce=%s" % (
            raw["raw_len"], raw["n_blocks"], raw["eg_port"], raw["nonce"]
        )

    return "short len=%s pn=%s spin=%s dcid=%s%s" % (
        info.get("quic_len"),
        info.get("pn"),
        info.get("spin"),
        info.get("dcid"),
        extra,
    )


def send_quic(quic_payload: bytes, label: str) -> None:
    pkt = build_l2_packet(quic_payload)
    print("[SEND] %-22s %s:%s -> %s:%s quic_len=%d" % (
        label, pkt[scapy.IP].src, pkt[scapy.UDP].sport, pkt[scapy.IP].dst, pkt[scapy.UDP].dport, len(quic_payload)
    ))
    scapy.sendp(pkt, iface=SERVER_IFACE, verbose=False)


def packet_is_from_client(pkt) -> bool:
    return (
        scapy.Ether in pkt and scapy.IP in pkt and scapy.UDP in pkt and scapy.Raw in pkt
        and pkt[scapy.Ether].src.lower() == CLIENT_MAC
        and pkt[scapy.IP].src == CLIENT_IP
        and int(pkt[scapy.UDP].dport) == UDP_DPORT
    )


def main() -> None:
    expected_data_size = get_data_size()
    require_iface(SERVER_IFACE)

    print("QU4C DUT server")
    print("iface=%s %s/%s <- %s/%s" % (SERVER_IFACE, SERVER_IP, SERVER_MAC, CLIENT_IP, CLIENT_MAC))
    print("SERVER_CID/DCID=%s" % SERVER_CID)
    print("expected_data_size=%d raw_len=%d" % (expected_data_size, raw_chacha_len(expected_data_size)))

    state = {
        "sent_handshake": False,
        "acked_first_request": False,
        "pktgen_like": 0,
        "server_long_pn": 0,
        "server_short_pn": 0,
    }

    def on_rx(pkt):
        if not packet_is_from_client(pkt):
            return

        try:
            info = parse_quic(bytes(pkt[scapy.Raw]))
        except Exception as exc:
            print("[WARN] client packet parse failed:", exc)
            return

        print("[RX] client", summary(info))

        if info.get("header_form") == 1 and info.get("packet_type") == 0 and not state["sent_handshake"]:
            p1 = build_long_packet(SERVER_HANDSHAKE_BIG_LEN, 2, CLIENT_CID, SERVER_CID, state["server_long_pn"])
            send_quic(p1, "server handshake-big")
            state["server_long_pn"] += 1

            time.sleep(SERVER_HANDSHAKE_GAP)

            p2 = build_long_packet(SERVER_HANDSHAKE_SMALL_LEN, 2, CLIENT_CID, SERVER_CID, state["server_long_pn"])
            send_quic(p2, "server handshake-small")
            state["server_long_pn"] += 1
            state["sent_handshake"] = True
            return

        raw = info.get("raw_chacha")
        if info.get("header_form") == 0 and info.get("dcid") == SERVER_CID and raw is not None:
            if not state["acked_first_request"]:
                if raw["data_size"] != expected_data_size:
                    print("[WARN] data_size received=%s expected=%s" % (raw["data_size"], expected_data_size))

                time.sleep(SERVER_ACK_DELAY)
                ack_payload = build_short_packet(CLIENT_CID, state["server_short_pn"], b"\x00" * (SERVER_ACK_LEN - 10), spin=info.get("spin", 0))
                send_quic(ack_payload, "server ack first request")
                state["server_short_pn"] += 1
                state["acked_first_request"] = True
                print("[INFO] first software request ACKed. Counting PktGen packets.")
            else:
                state["pktgen_like"] += 1
                if state["pktgen_like"] <= 5 or (state["pktgen_like"] % 1000) == 0:
                    print("[PKTGEN] count=%d last_pn=%s raw=%sB" % (
                        state["pktgen_like"], info.get("pn"), raw["raw_len"]
                    ))

    sniffer = scapy.AsyncSniffer(iface=SERVER_IFACE, store=False, prn=on_rx, promisc=True)
    sniffer.start()
    print("[INFO] server running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(SNIFF_SLICE)
    except KeyboardInterrupt:
        print("\n[INFO] server stopped. pktgen_like=%d acked_first_request=%s" % (
            state["pktgen_like"], state["acked_first_request"]
        ))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


main()
