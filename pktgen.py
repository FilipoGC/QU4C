#!/usr/bin/env python
import binascii
import os
import sys
import time

sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/tofino/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/bf_ptf/"))

import bfrt_grpc.client as gc
import grpc
from scapy.all import Ether, Raw

# bfrt connection

interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)
print("Connected to BF Runtime Server")

bfrt_info = interface.bfrt_info_get()
p4_name = bfrt_info.p4_name_get()
print("The target runs program", p4_name)

interface.bind_pipeline_config(p4_name)

target_dev = gc.Target(device_id=0)
target_pipe0 = gc.Target(device_id=0, pipe_id=0)

# pktgen Tables
pktgen_app_cfg_table = bfrt_info.table_get("pktgen.app_cfg")
pktgen_pkt_buffer_table = bfrt_info.table_get("pktgen.pkt_buffer")
pktgen_port_cfg_table = bfrt_info.table_get("pktgen.port_cfg")

app_id = 1

pgen_dev_port = 68
pgen_pipe_local_source_port = 68

buff_offset = 144

# packet creation
print("Create packet")

src_mac = "00:1b:21:a5:85:c8"
dst_mac = "90:e2:ba:27:fd:3d"  #
eg_port = 50

nonce_hex = "0000000000000000"
n_block = 6

# chacha_pre_h:
# bit<1> mode | bit<7> pad | bit<8> data_pos | bit<8> round | bit<7> pad2 | bit<9> eg_port
first_byte = 0x80  # mode=1, pad=0
chacha_pre = bytes([first_byte, 0x00, 0x00]) + int(eg_port).to_bytes(2, byteorder="big")

nonce = binascii.unhexlify(nonce_hex)
data = b"\x00" * (64 * n_block)

payload = chacha_pre + nonce + data
pkt = bytes(Ether(src=src_mac, dst=dst_mac, type=0x9000) / Raw(payload))
pktlen = len(pkt)

print("payload bytes =", len(payload))
print("frame bytes   =", pktlen)

# enable pktgen port
print("Enable pktgen port {}".format(pgen_dev_port))

pktgen_port_cfg_table.entry_mod(
    target_dev,
    [pktgen_port_cfg_table.make_key([gc.KeyTuple("dev_port", pgen_dev_port)])],
    [pktgen_port_cfg_table.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
)

# configure packet buffer

print("Configure packet buffer")

pktgen_pkt_buffer_table.entry_mod(
    target_dev,
    [
        pktgen_pkt_buffer_table.make_key(
            [
                gc.KeyTuple("pkt_buffer_offset", buff_offset),
                gc.KeyTuple("pkt_buffer_size", pktlen),
            ]
        )
    ],
    [pktgen_pkt_buffer_table.make_data([gc.DataTuple("buffer", bytearray(pkt))])],
)

# trigger settings
print("Configure pktgen application app_id={}".format(app_id))

app_key = pktgen_app_cfg_table.make_key([gc.KeyTuple("app_id", app_id)])

app_data = pktgen_app_cfg_table.make_data(
    [
        gc.DataTuple("timer_nanosec", 1000),  # 200000
        gc.DataTuple("app_enable", bool_val=False),
        gc.DataTuple("pkt_len", pktlen),
        gc.DataTuple("pkt_buffer_offset", buff_offset),
        gc.DataTuple("pipe_local_source_port", pgen_pipe_local_source_port),
        gc.DataTuple("increment_source_port", bool_val=False),
        gc.DataTuple("batch_count_cfg", 0),
        gc.DataTuple("packets_per_batch_cfg", 127),
        gc.DataTuple("ibg", 0),
        gc.DataTuple("ibg_jitter", 0),
        gc.DataTuple("ipg", 0),  # 6000
        gc.DataTuple("ipg_jitter", 0),
        gc.DataTuple("batch_counter", 0),
        gc.DataTuple("pkt_counter", 0),
        gc.DataTuple("trigger_counter", 0),
    ],
    "trigger_timer_periodic",
)

pktgen_app_cfg_table.entry_mod(target_pipe0, [app_key], [app_data])

# enable pktgen
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

# monitoring loop(debug)

# print("Pktgen running on pipe 0 / source port 68")
# print("Press Ctrl+C to stop")
# try:
#     while True:
#         time.sleep(1)

#         resp = pktgen_app_cfg_table.entry_get(
#             target_pipe0, [app_key], {"from_hw": False}
#         )
#         data_dict = next(resp)[0].to_dict()

#         print(
#             "trigger_counter={} batch_counter={} pkt_counter={}".format(
#                 data_dict.get("trigger_counter", "NA"),
#                 data_dict.get("batch_counter", "NA"),
#                 data_dict.get("pkt_counter", "NA"),
#             )
#         )

# except KeyboardInterrupt:
#     print("\nDisable pktgen")

#     pktgen_app_cfg_table.entry_mod(
#         target_pipe0,
#         [app_key],
#         [
#             pktgen_app_cfg_table.make_data(
#                 [gc.DataTuple("app_enable", bool_val=False)], "trigger_timer_periodic"
#             )
#         ],
#     )

#     print("Stopped")
