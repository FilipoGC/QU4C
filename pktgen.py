#!/usr/bin/env python3
import binascii
import os
import sys
from param import (
    DATA_BLOCKS,
    DATA_SIZE,
    RAW_CHACHA_LEN,
    QUIC_PAYLOAD_LEN,
    UDP_LEN,
    IPV4_TOTAL_LEN,
    OUTPUT_FRAME_LEN,
    PKTGEN_INPUT_FRAME_LEN,
)

sys.path.append(os.path.expandvars("$SDE/install/lib/python3.10/site-packages/tofino/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.10/site-packages/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.10/site-packages/bf_ptf/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/tofino/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/bf_ptf/"))

import bfrt_grpc.client as gc
from scapy.all import Ether, Raw

APP_ID = 1
PGEN_DEV_PORT = 68
PGEN_PIPE_LOCAL_SOURCE_PORT = 68
BUFFER_OFFSET = 144
TIMER_NS = 1000
BATCH_COUNT_CFG = 0
PACKETS_PER_BATCH_CFG = 127
EG_PORT = 50

SRC_MAC = "ac:1f:6b:67:06:70"
DST_MAC = "c4:70:bd:8b:c8:0c"
NONCE_HEX = "0000000000000000"


def main() -> None:
    interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)
    print("Connected to BF Runtime Server")

    bfrt_info = interface.bfrt_info_get()
    p4_name = bfrt_info.p4_name_get()
    print("The target runs program", p4_name)
    interface.bind_pipeline_config(p4_name)

    target_dev = gc.Target(device_id=0)
    target_pipe0 = gc.Target(device_id=0, pipe_id=0)

    pktgen_app_cfg_table = bfrt_info.table_get("pktgen.app_cfg")
    pktgen_pkt_buffer_table = bfrt_info.table_get("pktgen.pkt_buffer")
    pktgen_port_cfg_table = bfrt_info.table_get("pktgen.port_cfg")

    print("Create packet")
    print(
        f"DATA_BLOCKS={DATA_BLOCKS} data={DATA_SIZE}B "
        f"raw_chacha={RAW_CHACHA_LEN}B quic_payload={QUIC_PAYLOAD_LEN}B "
        f"udp_len={UDP_LEN} ipv4_total={IPV4_TOTAL_LEN} "
        f"output_frame={OUTPUT_FRAME_LEN}B pktgen_input_frame={PKTGEN_INPUT_FRAME_LEN}B"
    )

    first_byte = 0x80
    chacha_pre = bytes([first_byte, 0x00, 0x00]) + int(EG_PORT).to_bytes(2, byteorder="big")
    nonce = binascii.unhexlify(NONCE_HEX)
    data = b"\x00" * DATA_SIZE

    payload = chacha_pre + nonce + data
    pkt = bytes(Ether(src=SRC_MAC, dst=DST_MAC, type=0x9000) / Raw(payload))
    pktlen = len(pkt)

    if pktlen != PKTGEN_INPUT_FRAME_LEN:
        raise SystemExit(f"Internal length mismatch: pktlen={pktlen} expected={PKTGEN_INPUT_FRAME_LEN}")

    print("payload bytes =", len(payload))
    print("frame bytes   =", pktlen)

    app_key = pktgen_app_cfg_table.make_key([gc.KeyTuple("app_id", APP_ID)])

    print(f"Enable pktgen port {PGEN_DEV_PORT}")
    pktgen_port_cfg_table.entry_mod(
        target_dev,
        [pktgen_port_cfg_table.make_key([gc.KeyTuple("dev_port", PGEN_DEV_PORT)])],
        [pktgen_port_cfg_table.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
    )

    print("Configure packet buffer")
    pktgen_pkt_buffer_table.entry_mod(
        target_dev,
        [
            pktgen_pkt_buffer_table.make_key(
                [
                    gc.KeyTuple("pkt_buffer_offset", BUFFER_OFFSET),
                    gc.KeyTuple("pkt_buffer_size", pktlen),
                ]
            )
        ],
        [pktgen_pkt_buffer_table.make_data([gc.DataTuple("buffer", bytearray(pkt))])],
    )

    print(f"Configure pktgen application app_id={APP_ID}")
    app_data = pktgen_app_cfg_table.make_data(
        [
            gc.DataTuple("timer_nanosec", TIMER_NS),
            gc.DataTuple("app_enable", bool_val=False),
            gc.DataTuple("pkt_len", pktlen),
            gc.DataTuple("pkt_buffer_offset", BUFFER_OFFSET),
            gc.DataTuple("pipe_local_source_port", PGEN_PIPE_LOCAL_SOURCE_PORT),
            gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", BATCH_COUNT_CFG),
            gc.DataTuple("packets_per_batch_cfg", PACKETS_PER_BATCH_CFG),
            gc.DataTuple("ibg", 0),
            gc.DataTuple("ibg_jitter", 0),
            gc.DataTuple("ipg", 0),
            gc.DataTuple("ipg_jitter", 0),
            gc.DataTuple("batch_counter", 0),
            gc.DataTuple("pkt_counter", 0),
            gc.DataTuple("trigger_counter", 0),
        ],
        "trigger_timer_periodic",
    )
    pktgen_app_cfg_table.entry_mod(target_pipe0, [app_key], [app_data])

    print("Enable pktgen")
    pktgen_app_cfg_table.entry_mod(
        target_pipe0,
        [app_key],
        [
            pktgen_app_cfg_table.make_data(
                [gc.DataTuple("app_enable", bool_val=True)], "trigger_timer_periodic"
            )
        ],
    )


if __name__ == "__main__":
    main()
