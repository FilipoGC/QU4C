#!/usr/bin/env python3
import os
import sys
import time

for path in (
    "$SDE/install/lib/python3.10/site-packages/tofino/bfrt_grpc",
    "$SDE/install/lib/python3.10/site-packages/tofino/",
    "$SDE/install/lib/python3.10/site-packages/",
    "$SDE/install/lib/python3.6/site-packages/tofino/bfrt_grpc",
    "$SDE/install/lib/python3.6/site-packages/tofino/",
    "$SDE/install/lib/python3.6/site-packages/",
):
    sys.path.append(os.path.expandvars(path))

import bfrt_grpc.client as gc  # noqa: E402  # pyright: ignore[reportMissingImports]


GRPC_ADDR = "localhost:50052"
CLIENT_ID = 2
DEVICE_ID = 0
PORT = 52
INTERVAL = 1.0

COUNTER_TABLE = "MyEgressControl.eg_port_counter"

PKT_FIELDS = ("$COUNTER_SPEC_PKTS", "$COUNTER_SPEC_PACKETS", "packets", "pkts")
BYTE_FIELDS = ("$COUNTER_SPEC_BYTES", "bytes")
KEY_FIELDS = ("$COUNTER_INDEX", "COUNTER_INDEX", "index", "idx")


def as_int(value):
    if isinstance(value, dict):
        if "value" in value:
            return int(value["value"])
        if "low" in value:
            return int(value["low"])
    return int(value)


def get_field(data, names):
    for name in names:
        if name in data:
            return as_int(data[name])
    raise KeyError(sorted(data.keys()))


def get_key_name(table):
    names = list(table.info.key_field_name_list_get())
    for name in KEY_FIELDS:
        if name in names:
            return name
    return names[0]


def read_counter(table, target, key_name):
    key = table.make_key([gc.KeyTuple(key_name, PORT)])
    resp = table.entry_get(target, [key], {"from_hw": True})
    data, _ = next(resp)
    data = data.to_dict()

    pkts = get_field(data, PKT_FIELDS)
    bytes_ = get_field(data, BYTE_FIELDS)

    return pkts, bytes_


def main():
    interface = gc.ClientInterface(GRPC_ADDR, client_id=CLIENT_ID, device_id=DEVICE_ID)

    bfrt_info = interface.bfrt_info_get()
    p4_name = bfrt_info.p4_name_get()

    interface.bind_pipeline_config(p4_name)
    bfrt_info = interface.bfrt_info_get()

    target = gc.Target(device_id=DEVICE_ID, pipe_id=0xFFFF)
    table = bfrt_info.table_get(COUNTER_TABLE)
    key_name = get_key_name(table)

    print(f"Monitoring {COUNTER_TABLE}[{PORT}]")
    print(f"{'PORT':>5} {'Mpps':>12} {'Gbps':>12} {'pkts_total':>18} {'bytes_total':>18}")

    prev_pkts, prev_bytes = read_counter(table, target, key_name)
    prev_t = time.monotonic()

    while True:
        time.sleep(INTERVAL)

        now = time.monotonic()
        pkts, bytes_ = read_counter(table, target, key_name)

        dt = now - prev_t
        dpkts = pkts - prev_pkts
        dbytes = bytes_ - prev_bytes

        if dpkts < 0:
            dpkts += 1 << 64
        if dbytes < 0:
            dbytes += 1 << 64

        mpps = dpkts / dt / 1e6
        gbps = dbytes * 8 / dt / 1e9

        print(f"{PORT:5d} {mpps:12.3f} {gbps:12.3f} {pkts:18d} {bytes_:18d}", flush=True)

        prev_pkts = pkts
        prev_bytes = bytes_
        prev_t = now


main()
