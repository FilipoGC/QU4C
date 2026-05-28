#!/usr/bin/env python3
import os
import sys
from param import DATA_BLOCKS, DATA_SIZE

sys.path.append(os.path.expandvars("$SDE/install/lib/python3.10/site-packages/tofino/bfrt_grpc"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.10/site-packages/tofino/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.10/site-packages/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/tofino/bfrt_grpc"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/tofino/"))
sys.path.append(os.path.expandvars("$SDE/install/lib/python3.6/site-packages/"))

import bfrt_grpc.client as gc  # pyright: ignore[reportMissingImports]

print(sys.version)

interface = gc.ClientInterface("localhost:50052", client_id=1, device_id=0)
bfrt_info = interface.bfrt_info_get()
p4_name = bfrt_info.p4_name_get()
interface.bind_pipeline_config(p4_name)
bfrt_info = interface.bfrt_info_get()
target = gc.Target(device_id=0, pipe_id=0xFFFF)

print("DATA_BLOCKS:", DATA_BLOCKS, "data size:", DATA_SIZE, "bytes")

recir_ports = [
    0,
    4,
    8,
    16,
    24,
    32,
    40,
    48,
    56,
    132,
    136,
    140,
    144,
    152,
    160,
    168,
    176,
    184,
]
print("n_recir_port:", len(recir_ports))

n_cls = len(recir_ports)
width = 32

th = [(1 << width) * i // n_cls for i in range(n_cls + 1)]

key_set = set()
keys = []
data = []

for i in range(0, n_cls):
    lb = th[i]
    ub = th[i + 1]

    for j in reversed(range(width + 1)):
        if ub & (1 << j) == 0:
            continue
        mask = 1 << j
        key = (ub & ~(mask - 1)) ^ mask
        if (key, width - j) not in key_set:
            key_set.add((key, width - j))
            keys.append((key, width - j))
            data.append(i)


i7_table = bfrt_info.table_get("MyIngressControl.tb_i7")

key_list = [
    i7_table.make_key(
        [
            gc.KeyTuple("hdr.chacha_pre.data_pos", DATA_BLOCKS, 255),
            gc.KeyTuple("meta.recir_random", 0, 0),
        ]
    )
]

data_list = [i7_table.make_data([], "MyIngressControl.i7_app")]

for i in range(len(keys)):
    key_list.append(
        i7_table.make_key(
            [
                gc.KeyTuple("hdr.chacha_pre.data_pos", 0, 0),
                gc.KeyTuple(
                    "meta.recir_random",
                    keys[i][0],
                    ((1 << keys[i][1]) - 1) << (32 - keys[i][1]),
                ),
            ]
        )
    )
    data_list.append(
        i7_table.make_data(
            [gc.DataTuple("eg_port", recir_ports[data[i]])], "MyIngressControl.i7"
        )
    )

try:
    i7_table.entry_del(target, [])
except Exception as exc:
    print("Warning: could not clear tb_i7 before programming:", exc)

i7_table.entry_add(target, key_list, data_list)
print("Installed tb_i7 entries:", len(key_list))
