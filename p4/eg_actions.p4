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

#include "param.h"

    action e0() {
        hdr.chacha.state0 = hdr.chacha.state0 + hdr.chacha.state5;
        hdr.chacha.state1 = hdr.chacha.state1 + hdr.chacha.state6;
        hdr.chacha.state2 = hdr.chacha.state2 + hdr.chacha.state7;
        hdr.chacha.state3 = hdr.chacha.state3 + hdr.chacha.state4;
    }

    action e1() {
        hdr.nonce.state15 = hdr.nonce.state15 ^ hdr.chacha.state0;
        hdr.chacha.state12 = hdr.chacha.state12 ^ hdr.chacha.state1;
        hdr.chacha.state13 = hdr.chacha.state13 ^ hdr.chacha.state2;
        hdr.nonce.state14 = hdr.nonce.state14 ^ hdr.chacha.state3;
    }

    action e2() {
        hdr.chacha.state10 = hdr.chacha.state10 + copy32_0.get({hdr.nonce.state15[15:0] ++ hdr.nonce.state15[31:16]});
        hdr.nonce.state15 = hdr.nonce.state15[15:0] ++ hdr.nonce.state15[31:16];
        hdr.chacha.state12 = hdr.chacha.state12[15:0] ++ hdr.chacha.state12[31:16];
        hdr.chacha.state13 = hdr.chacha.state13[15:0] ++ hdr.chacha.state13[31:16];
        hdr.nonce.state14 = hdr.nonce.state14[15:0] ++ hdr.nonce.state14[31:16];
    }

    action e3() {
        hdr.chacha.state5 = hdr.chacha.state5 ^ hdr.chacha.state10;
        hdr.chacha.state11 = hdr.chacha.state11 + hdr.chacha.state12;
        hdr.chacha.state8 = hdr.chacha.state8 + hdr.chacha.state13;
        hdr.chacha.state9 = hdr.chacha.state9 + hdr.nonce.state14;
    }

    action e4() {
        hdr.chacha.state5 = hdr.chacha.state5[19:0] ++ hdr.chacha.state5[31:20];
        hdr.chacha.state6 = hdr.chacha.state6 ^ hdr.chacha.state11;
        hdr.chacha.state7 = hdr.chacha.state7 ^ hdr.chacha.state8;
        hdr.chacha.state4 = hdr.chacha.state4 ^ hdr.chacha.state9;
    }

    action e5() {
        hdr.chacha.state0 = hdr.chacha.state0 + hdr.chacha.state5;
        hdr.chacha.state1 = hdr.chacha.state1 + copy32_1.get({hdr.chacha.state6[19:0] ++ hdr.chacha.state6[31:20]});
        hdr.chacha.state6 = hdr.chacha.state6[19:0] ++ hdr.chacha.state6[31:20];
        hdr.chacha.state7 = hdr.chacha.state7[19:0] ++ hdr.chacha.state7[31:20];
        hdr.chacha.state4 = hdr.chacha.state4[19:0] ++ hdr.chacha.state4[31:20];
    }

    action e6() {
        hdr.nonce.state15 = hdr.nonce.state15 ^ hdr.chacha.state0;
        hdr.chacha.state12 = hdr.chacha.state12 ^ hdr.chacha.state1;
        hdr.chacha.state2 = hdr.chacha.state2 + hdr.chacha.state7;
        hdr.chacha.state3 = hdr.chacha.state3 + hdr.chacha.state4;
    }

    action e7() {
        hdr.nonce.state15 = hdr.nonce.state15[23:0] ++ hdr.nonce.state15[31:24];
        hdr.chacha.state12 = hdr.chacha.state12[23:0] ++ hdr.chacha.state12[31:24];
        hdr.chacha.state13 = hdr.chacha.state13 ^ hdr.chacha.state2;
        hdr.nonce.state14 = hdr.nonce.state14 ^ hdr.chacha.state3;
    }

    action e8() {
        hdr.chacha.state10 = hdr.chacha.state10 + hdr.nonce.state15;
        hdr.chacha.state11 = hdr.chacha.state11 + hdr.chacha.state12;
        hdr.chacha.state8 = hdr.chacha.state8 + copy32_2.get({hdr.chacha.state13[23:0] ++ hdr.chacha.state13[31:24]});
        hdr.chacha.state13 = hdr.chacha.state13[23:0] ++ hdr.chacha.state13[31:24];
        hdr.nonce.state14 = hdr.nonce.state14[23:0] ++ hdr.nonce.state14[31:24];
    }

    action e9() {
        hdr.chacha.state5 = hdr.chacha.state5 ^ hdr.chacha.state10;
        hdr.chacha.state6 = hdr.chacha.state6 ^ hdr.chacha.state11;
        hdr.chacha.state7 = hdr.chacha.state7 ^ hdr.chacha.state8;
        hdr.chacha.state9 = hdr.chacha.state9 + hdr.nonce.state14;
    }

    action e10(bit<32> key0) {
        hdr.chacha.state5 = hdr.chacha.state5[24:0] ++ hdr.chacha.state5[31:25];
        hdr.chacha.state6 = hdr.chacha.state6[24:0] ++ hdr.chacha.state6[31:25];
        hdr.chacha.state7 = hdr.chacha.state7[24:0] ++ hdr.chacha.state7[31:25];
        hdr.chacha.state4 = hdr.chacha.state4 ^ hdr.chacha.state9;

        meta.key0 = key0;
    }

    action e11() {
        hdr.chacha.state4 = hdr.chacha.state4[24:0] ++ hdr.chacha.state4[31:25];

        hdr.chacha_pre.round = hdr.chacha_pre.round + 1;
    }

    action e11_fin(
            bit<32> key1, bit<32> key2, bit<32> key3,
            bit<32> key4, bit<32> key5, bit<32> key6, bit<32> key7,
            bit<32> data_pos
        ) {
        hdr.chacha.state0 = hdr.chacha.state0 + CONST0;
        hdr.chacha.state1 = hdr.chacha.state1 + CONST1;
        hdr.chacha.state2 = hdr.chacha.state2 + CONST2;
        hdr.chacha.state3 = hdr.chacha.state3 + CONST3;

        // hdr.chacha.state4 = copy32_3.get({hdr.chacha.state4[24:0] ++ hdr.chacha.state4[31:25]}) + key0;
        hdr.chacha.state4 = copy32_3.get({hdr.chacha.state4[24:0] ++ hdr.chacha.state4[31:25]}) + meta.key0;

        hdr.chacha.state5 = hdr.chacha.state5 + key1;
        hdr.chacha.state6 = hdr.chacha.state6 + key2;
        hdr.chacha.state7 = hdr.chacha.state7 + key3;
        hdr.chacha.state8 = hdr.chacha.state8 + key4;
        hdr.chacha.state9 = hdr.chacha.state9 + key5;
        hdr.chacha.state10 = hdr.chacha.state10 + key6;
        hdr.chacha.state11 = hdr.chacha.state11 + key7;

        hdr.chacha.state12 = hdr.chacha.state12 + data_pos;
        hdr.chacha.state13 = hdr.chacha.state13 + 0;

        hdr.nonce.state14 = hdr.nonce.state14 + hdr.nonce_initial.state14;
        hdr.nonce.state15 = hdr.nonce.state15 + hdr.nonce_initial.state15;

        hdr.chacha_pre.data_pos = hdr.chacha_pre.data_pos + 1;
        hdr.chacha_pre.round = 0;
    }

    action e11_app() {
        hdr.chacha.setInvalid();
        hdr.nonce.setInvalid();

        hdr.ethernet.ether_type = ETHERTYPE_IPV4;

		hdr.ipv4.setValid();
		hdr.ipv4.version        = 4w4;
		hdr.ipv4.ihl            = 4w5;
		hdr.ipv4.diffserv       = 8w0;
		hdr.ipv4.total_len      = 16w435;   // 20 + 8 + 407
		hdr.ipv4.identification = 16w1;
		hdr.ipv4.flags          = 3w2;      // DF, para ficar parecido com o trace
		hdr.ipv4.frag_offset    = 13w0;
		hdr.ipv4.ttl            = 8w64;
		hdr.ipv4.protocol       = 8w17;
		hdr.ipv4.hdr_checksum   = 16w0;
		hdr.ipv4.src_addr       = 32w0x0D0D0D37;   // 13.13.13.55
		hdr.ipv4.dst_addr       = 32w0x0D0D0D32;   // 13.13.13.50

		hdr.udp.setValid();
		hdr.udp.src_port        = 16w52005;
		hdr.udp.dst_port        = 16w4433;
		hdr.udp.hdr_length      = 16w415;   // 8 + 407
		hdr.udp.checksum        = 16w0;

		hdr.quic_short.setValid();

		//hdr.quic_short.flags = 8w0x40 | ((bit<8>)hdr.chacha_pre.eg_port[0:0] << 5);
		hdr.quic_short.flags = hdr.ethernet.dst_addr[7:0];
		hdr.quic_short.dcid = 64w0x5e1eb1799edb1083;
		hdr.quic_short.packet_number = 8w3 + hdr.ethernet.src_addr[7:0];

		hdr.ethernet.src_addr = 48w0x001b21a585c8;
		hdr.ethernet.dst_addr = 48w0x90e2ba27fd3d;
    }
