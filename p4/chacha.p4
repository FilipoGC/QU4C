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
#include <core.p4>
#include <tna.p4>

#include "common/headers.p4"
#include "common/util.p4"
#include "param.h"

// Please use bf-sde v9.9.0 or later

header chacha_pre_h {
    bit<1> mode;    // 0 (decrypt) / 1 (encrypt)
    bit<7> pad;     // fill with 0
    bit<8> data_pos;
    bit<8> round;

    bit<7> pad2;
    bit<9> eg_port;
}


header chacha_h {
    bit<32> state0;  bit<32> state1;  bit<32> state2;  bit<32> state3;
    bit<32> state4;  bit<32> state5;  bit<32> state6;  bit<32> state7;
    bit<32> state8;  bit<32> state9;  bit<32> state10; bit<32> state11;
    bit<32> state12; bit<32> state13;
}

header nonce_h {
    bit<32> state14;
    bit<32> state15;
}

header data_h {
    bit<32> data0;  bit<32> data1;  bit<32> data2;  bit<32> data3;
    bit<32> data4;  bit<32> data5;  bit<32> data6;  bit<32> data7;
    bit<32> data8;  bit<32> data9;  bit<32> data10; bit<32> data11;
    bit<32> data12; bit<32> data13; bit<32> data14; bit<32> data15;
}

struct headers {
	pktgen_timer_header_t timer;

    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
	quic_short_h quic_short;

    chacha_pre_h chacha_pre;
    nonce_h nonce_initial;
    chacha_h chacha;
    nonce_h nonce;

#if DATA_BLOCKS >= 2
    data_h data_t0;
#endif
#if DATA_BLOCKS >= 3
    data_h data_t1;
#endif
#if DATA_BLOCKS >= 4
    data_h data_t2;
#endif
#if DATA_BLOCKS >= 5
    data_h data_t3;
#endif
#if DATA_BLOCKS >= 6
    data_h data_t4;
#endif
    data_h data;
}

struct ig_metadata {
    nonce_h nonce;

    bit<32> recir_random;
    bit<1>  do_cipher;
}

struct eg_metadata {
    bit<32> key0;
    bit<1>  spin_carrier;
}

parser MyIngressParser(packet_in pkt,
                out headers hdr,
                out ig_metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : skip_port_metadata;
        }
    }

    state parse_resubmit {
        pkt.extract(meta.nonce);
        transition parse_ethernet;
    }

    state skip_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            68: parse_pktgen_timer;//generation port
            default: parse_ethernet;
        }
    }

    state parse_pktgen_timer {
        pkt.extract(hdr.timer);
        transition parse_pktgen_ethernet_only;
    }

	state parse_pktgen_ethernet_only {
		pkt.extract(hdr.ethernet);
		transition accept;
	}
//inicio parser hibrido stack nova
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:    parse_ipv4;
            ETHERTYPE_CHACHA_RAW: parse_chacha_pre;
            default:           reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP:    parse_udp;
            default:             reject;
        }
    }

	state parse_udp {
		pkt.extract(hdr.udp);
		transition select(hdr.udp.hdr_length) {
		    UDP_HDR_LEN_BYTES: parse_quic_short;
		    default: accept;
		}
	}

	state parse_quic_short {
		pkt.extract(hdr.quic_short);
		transition parse_chacha_pre;
	}

//fim parser stack nova

    state parse_chacha_pre {
        pkt.extract(hdr.chacha_pre);

        transition select(hdr.chacha_pre.data_pos, hdr.chacha_pre.round) {
            (0, 0) : parse_nonce_initial;
            default: parse_chacha_initial;
        }
    }

    state parse_nonce_initial {
        pkt.extract(hdr.nonce_initial);
        transition select(ig_intr_md.resubmit_flag) {
            1 : skip_nonce;
            0 : set_nonce;
        }
    }

    state set_nonce {
        meta.nonce.state14 = hdr.nonce_initial.state14;
        meta.nonce.state15 = hdr.nonce_initial.state15;
        transition parse_data;
    }

    state skip_nonce {
        transition parse_data;
    }

    state parse_chacha_initial {
        pkt.extract(hdr.nonce_initial);
        meta.nonce.state14 = hdr.nonce_initial.state14;
        meta.nonce.state15 = hdr.nonce_initial.state15;
        transition parse_chacha;
    }

    state parse_chacha {
        pkt.extract(hdr.chacha);
        transition parse_nonce;
    }

    state parse_nonce {
        pkt.extract(hdr.nonce);
        transition select(hdr.chacha_pre.data_pos, hdr.chacha_pre.round) {
            (1, 0) : parse_data_rot;
            (2, 0) : parse_data_rot;
            (3, 0) : parse_data_rot;
            (4, 0) : parse_data_rot;
            (5, 0) : parse_data_rot;
            (6, 0) : parse_data_rot;
            default : parse_data;
        }
    }

    state parse_data {
#if DATA_BLOCKS >= 2
        pkt.extract(hdr.data_t0);
#endif
#if DATA_BLOCKS >= 3
        pkt.extract(hdr.data_t1);
#endif
#if DATA_BLOCKS >= 4
        pkt.extract(hdr.data_t2);
#endif
#if DATA_BLOCKS >= 5
        pkt.extract(hdr.data_t3);
#endif
#if DATA_BLOCKS >= 6
        pkt.extract(hdr.data_t4);
#endif
        pkt.extract(hdr.data);
        transition accept;
    }

    state parse_data_rot {
        pkt.extract(hdr.data);
#if DATA_BLOCKS >= 2
        pkt.extract(hdr.data_t0);
#endif
#if DATA_BLOCKS >= 3
        pkt.extract(hdr.data_t1);
#endif
#if DATA_BLOCKS >= 4
        pkt.extract(hdr.data_t2);
#endif
#if DATA_BLOCKS >= 5
        pkt.extract(hdr.data_t3);
#endif
#if DATA_BLOCKS >= 6
        pkt.extract(hdr.data_t4);
#endif
        transition accept;
    }

}

control MyIngressControl(inout headers hdr,
                inout ig_metadata meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Random<bit<32>>() random32_0;
    Random<bit<32>>() random32_1;
    Random<bit<32>>() random32_2;
	Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_0;
	Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;

    #include "ig_actions.p4"
    #include "ig_tables.p4"


    //actions e table pra encaminhar os pacotes entre cliente <-> servidor
	action set_from_recirc() {

	}

	action set_out_164_from_pktgen() {
	    hdr.ethernet.src_addr = 32w0x02020202 ++ hdr.timer.packet_id;
		hdr.ethernet.ether_type = ETHERTYPE_PKTGEN_FIRST;
        hdr.timer.setInvalid();
        ig_tm_md.ucast_egress_port = 164;
	}

	action set_out_130() {
    ig_tm_md.ucast_egress_port = 52;
    ig_tm_md.bypass_egress = 1w1;
    }

    action set_out_52() {
        ig_tm_md.ucast_egress_port = 130;
        ig_tm_md.bypass_egress = 1w1;
    }

	action drop_pkt() {
		ig_dprsr_md.drop_ctl = 1;
	}

	table mac_guard_xconnect {
    key = {
        ig_intr_md.ingress_port : exact;
    }
    actions = {
        set_out_130;
        set_out_52;
        set_out_164_from_pktgen;
        set_from_recirc;
        @defaultonly drop_pkt;
    }
    const default_action = drop_pkt();
    size = 8;
	}
	//end xconnect
    apply {

   	    if(hdr.chacha_pre.isValid()) {
			tb_i0.apply();
			tb_i1.apply();
			tb_i2.apply();
			tb_i3.apply();
			tb_i4.apply();
			tb_i5.apply();
			tb_i6.apply();
			tb_i7.apply();
			tb_i8.apply();
			tb_i9.apply();
			tb_i10.apply();
			tb_i11.apply();
		}else{
			mac_guard_xconnect.apply();
		}

		if (ig_dprsr_md.drop_ctl != 0) {
            return;
    	}
    }
}

control MyIngressDeparser(
                packet_out pkt,
                inout headers hdr,
                in ig_metadata meta,
                in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Resubmit() resubmit;

    apply {
        if (ig_dprsr_md.resubmit_type == 1) {
            resubmit.emit();
        } else if (ig_dprsr_md.resubmit_type == 2) {
            resubmit.emit(meta.nonce);
        }

        pkt.emit(hdr);
    }
}

parser MyEgressParser(
    packet_in pkt,
    out headers hdr,
    out eg_metadata meta,
    out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
		tofino_parser.apply(pkt, eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		meta.spin_carrier = hdr.ethernet.src_addr[0:0];
		transition select(hdr.ethernet.ether_type) {
        ETHERTYPE_PKTGEN_FIRST: accept;        // primeira passada: não parseia chacha
        ETHERTYPE_CHACHA_RAW:   parse_chacha;  // segunda passada
        ETHERTYPE_IPV4:         parse_ipv4;
        default:                reject;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
		    IP_PROTOCOLS_UDP: parse_udp;
		    default: reject;
		}
	}

	state parse_udp {
		pkt.extract(hdr.udp);
		transition select(hdr.udp.hdr_length) {
		    UDP_HDR_LEN_BYTES: parse_quic_short;
		    default: accept;
		}
	}

	state parse_quic_short {
		pkt.extract(hdr.quic_short);
		transition parse_chacha;
	}
//fim parser upv4 udp quic
    state parse_chacha {
        pkt.extract(hdr.chacha_pre);
        pkt.extract(hdr.nonce_initial);
        pkt.extract(hdr.chacha);
        pkt.extract(hdr.nonce);
        transition accept;
    }
}


control MyEgressControl(
    inout headers hdr,
    inout eg_metadata meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

	Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_0;
	Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;
	Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_2;
	Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_3;

    //counter definition, get packets/bytes sent to D_P 52.
    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS_AND_BYTES) eg_port_counter;


    #include "eg_actions.p4"
    #include "eg_tables.p4"
    //actions e table spin bit quic
    action set_spin_40() {
        hdr.ethernet.dst_addr = 40w0x0000000000 ++ 8w0x40;
    }
    action set_spin_60() {
        hdr.ethernet.dst_addr = 40w0x0000000000 ++ 8w0x60;
    }

    table tb_spin_quic {
        key = {
            hdr.chacha_pre.data_pos : exact;
            hdr.chacha_pre.round    : exact;
            meta.spin_carrier       : exact;
        }
        actions = {
            set_spin_40;
            set_spin_60;
            NoAction;
        }
        const default_action = NoAction();
        size = 4;
    }

    //
    apply {

        //Counting all packets in egress filtered by port (in our case 52)
        eg_port_counter.count(eg_intr_md.egress_port);

    	if (hdr.chacha_pre.isValid()){
		    tb_e0.apply();
		    tb_e1.apply();
		    tb_e2.apply();
		    tb_e3.apply();
		    tb_e4.apply();
		    tb_e5.apply();
		    tb_e6.apply();
		    tb_e7.apply();
		    tb_e8.apply();
		    tb_e9.apply();
		    tb_e10.apply();
			tb_spin_quic.apply();
		    tb_e11.apply();
    	} else {//ja dei bypass de pacotes handshake, aqui soh vem do pktgen 1st passada
            hdr.ethernet.ether_type = ETHERTYPE_CHACHA_RAW;
    	}


	}
}

control MyEgressDeparser(
    packet_out pkt,
    inout headers hdr,
    in eg_metadata meta,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

	Checksum() ipv4_csum;

    apply {
    	//checksum ipv4
    if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_csum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,

                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        pkt.emit(hdr);
    }
}


Pipeline(
    MyIngressParser(),
    MyIngressControl(),
    MyIngressDeparser(),
    MyEgressParser(),
    MyEgressControl(),
    MyEgressDeparser()) pipe;

Switch(pipe) main;
