/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/

 /*******************************************************************************
 * Modified on 2026-04-02.
 * This file extends the original ChaCha-Tofino implementation with new
 * functionality and adaptations for our use case.
 *
 * Based on:
 * Hasegawa-Laboratory, ChaCha-Tofino
 * https://github.com/Hasegawa-Laboratory/ChaCha-Tofino
 *
 * This modified file is distributed under the GNU Affero General Public License v3.0
 * (or any later version, if applicable). See the LICENSE file for details.
 ******************************************************************************/

#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_CHACHA_RAW = 16w0x9000;
const ether_type_t ETHERTYPE_PKTGEN_FIRST = 16w0x9001;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}


header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header quic_short_h {
    bit<8>  flags;
    bit<64> dcid;
    bit<8>  packet_number;
}

struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _HEADERS_ */
