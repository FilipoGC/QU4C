from param import DATA_BLOCKS


print("auxTables DATA_BLOCKS:", DATA_BLOCKS)

p4 = bfrt.chacha.pipe # pyright: ignore[reportMissingImports]
tbl = p4.MyIngressControl.mac_guard_xconnect

#forward table, client <-> server(handshake pkts) and pktgen + recirc pkts
tbl.entry_with_set_out_130(ingress_port=130).push()
tbl.entry_with_set_out_52(ingress_port=52).push()
tbl.entry_with_set_out_164_from_pktgen(ingress_port=68).push()
tbl.entry_with_set_from_recirc(ingress_port=164).push()

spin = p4.MyEgressControl.tb_spin_quic
spin.entry_with_set_spin_40(data_pos=DATA_BLOCKS, round=0, spin_carrier=0).push()
spin.entry_with_set_spin_60(data_pos=DATA_BLOCKS, round=0, spin_carrier=1).push()

bfrt.complete_operations() # noqa: F821 (annoying notification)

print("\n==== mac_guard_xconnect ====\n")
tbl.dump(table=True)
