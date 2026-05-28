#!/usr/bin/env python3
import sys


def generate(data_size):
    data_blocks = data_size // 64

    raw_chacha_len = 13 + data_size
    quic_payload_len = 10 + raw_chacha_len
    udp_len = 8 + quic_payload_len
    ipv4_total_len = 20 + udp_len
    output_frame_len = 14 + ipv4_total_len
    pktgen_input_frame_len = 14 + raw_chacha_len

    param = open("p4/param.h", "w")
    param.write("//generated from generate_params.py\n")
    param.write("#ifndef _PARAM_H_\n")
    param.write("#define _PARAM_H_\n")
    param.write("\n")
    param.write("#define CONST0 0x61707865\n")
    param.write("#define CONST1 0x3320646e\n")
    param.write("#define CONST2 0x79622d32\n")
    param.write("#define CONST3 0x6b206574\n")
    param.write("\n")
    param.write("#define ROUNDS_HALF 10\n")
    param.write(f"#define DATA_BLOCKS {data_blocks}\n")
    param.write(f"#define UDP_HDR_LEN_BYTES 16w{udp_len}\n")
    param.write(f"#define IPV4_TOTAL_LEN_BYTES 16w{ipv4_total_len}\n")
    param.write("\n")
    param.write("#define KEY0 0\n")
    param.write("#define KEY1 0\n")
    param.write("#define KEY2 0\n")
    param.write("#define KEY3 0\n")
    param.write("#define KEY4 0\n")
    param.write("#define KEY5 0\n")
    param.write("#define KEY6 0\n")
    param.write("#define KEY7 0\n")
    param.write("\n")
    param.write("#endif\n")
    param.close()

    py = open("param.py", "w")
    py.write("#generated from generate_params.py\n")
    py.write(f"DATA_BLOCKS = {data_blocks}\n")
    py.write(f"DATA_SIZE = {data_size}\n")
    py.write(f"RAW_CHACHA_LEN = {raw_chacha_len}\n")
    py.write(f"QUIC_PAYLOAD_LEN = {quic_payload_len}\n")
    py.write(f"UDP_LEN = {udp_len}\n")
    py.write(f"IPV4_TOTAL_LEN = {ipv4_total_len}\n")
    py.write(f"OUTPUT_FRAME_LEN = {output_frame_len}\n")
    py.write(f"PKTGEN_INPUT_FRAME_LEN = {pktgen_input_frame_len}\n")
    py.close()

    print(f"DATA_BLOCKS={data_blocks} data_size={data_size}B")


generate(int(sys.argv[1]))
