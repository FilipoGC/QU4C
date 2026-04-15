p4 = bfrt.chacha.pipe
tbl = p4.MyIngressControl.mac_guard_xconnect


# 50 -> 135
tbl.entry_with_set_out_135(
    ingress_port=130,
    # dst_addr=0x90e2ba27fd3d
).push()

# 135 -> 50
tbl.entry_with_set_out_50(
    ingress_port=52,
    # dst_addr=0x001b21a585c8
).push()

# 68 -> 164
tbl.entry_with_set_out_164_from_pktgen(
    ingress_port=68,
    # dst_addr=0x90e2ba27fd3d
).push()

# 164
tbl.entry_with_set_from_recirc(
    ingress_port=164,
    # dst_addr=0x90e2ba27fd3d
).push()

spin = p4.MyEgressControl.tb_spin_quic

spin.entry_with_set_spin_40(data_pos=6, round=0, spin_carrier=0).push()

spin.entry_with_set_spin_60(data_pos=6, round=0, spin_carrier=1).push()

bfrt.complete_operations()

print("\n==== mac_guard_xconnect ====\n")
tbl.dump(table=True)
