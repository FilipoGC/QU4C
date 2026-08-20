# ![](qu4c.png) Towards Reproducing QUIC Traffic on a P4-Based Programmable Switch


QU4C is based on the original ChaCha-Tofino project  
(https://github.com/Hasegawa-Laboratory/ChaCha-Tofino).

In this work, we extend the original implementation to parse and process emulated QUIC packets. The current version still includes hardcoded parameters, so users may need to adapt the port configuration to match their Tofino environment.

⚠️ This project is still under development and currently contains preliminary results and ongoing implementation efforts.

# Publication and references

QU4C is an artifact associated published at ACM SIGCOMM 2026: [DEMO: QU4C: High-Throughput QUIC Traffic Reproduction on Programmable Switches](https://dl.acm.org/doi/abs/10.1145/3789240.3830281).

# Requiriments
- Barefoot/Intel SDE
- BFRT Python libraries
- Python 3
- Scapy
- For the Python scripts to successfully process network configurations and for the SDE scripts to access hardware interfaces, **superuser (`sudo`) privileges are mandatory**.

# Usage
> We tested this project in Tofino-1 with Intel BF-SDE versions 9.12.0 and 9.13.2.

In Tofino, devports (D_P) are specific to each pipe/quad. QU4C must therefore be configured according to the quad organization of each Tofino switch. The Tofino PktGen is attached to quad 17 of each pipe, for example devports 68..71 in pipe 0, while the QCM (QU4C Cryptography Module) relies on resubmit operations, which are only supported on ports in quads 0..15. For this reason, the user must identify which quads and corresponding devports can be used for QCM recirculation/resubmit. Additionally, packets generated from the PktGen source port must be forwarded to a recirculation port in a resubmit-capable quad, so that they can enter the QCM processing path, see [Tofino Native Architecture](https://github.com/barefootnetworks/Open-Tofino/blob/master/PUBLIC_Tofino-Native-Arch.pdf) for more informations.

**Current example topology:**

| Component | Front-panel port | Device port (D_P) | Notes |
|---|---:|---:|---|
| Auxiliary client | `1/2` | `130` | Host that starts the emulated QUIC connection |
| DUT | `10/-` | `52` | Output port |
| PktGen source port | — | `68` | PktGen source port |
| PktGen loopback port | `28/-` | `164` | First recirculation used by PktGen packets |
| QCM port | `2/-` | `136` | MAC loopback |
| QCM port | `3/-` | `144` | MAC loopback |
| QCM port | `4/-` | `152` | MAC loopback |
| QCM port | `5/-` | `160` | MAC loopback |
| QCM port | `6/-` | `168` | MAC loopback |
| QCM port | `7/-` | `176` | MAC loopback |
| QCM port | `8/-` | `184` | MAC loopback |
| QCM port | `16/-` | `4` | MAC loopback |
| QCM port | `17/-` | `0` | MAC loopback |
| QCM port | `18/-` | `8` | MAC loopback |
| QCM port | `19/-` | `16` | MAC loopback |
| QCM port | `20/-` | `24` | MAC loopback |
| QCM port | `21/-` | `32` | MAC loopback |
| QCM port | `22/-` | `40` | MAC loopback |
| QCM port | `23/-` | `48` | MAC loopback |
| QCM port | `24/-` | `56` | MAC loopback |
| QCM port | `31/-` | `132` | MAC loopback |
| QCM port | `32/-` | `140` | MAC loopback |

**1. Set the ports of your own topology**

- Edit `portConfig.txt` to enable the corresponding physical ports of your topology. *The configured port speed must be compatible with the physical port capacity.*
- Edit **xconnect_table** in `auxTables.py` and the corresponding actions in `chacha.p4` to match with your DUT and Auxiliary client ports.
- Edit the action **i7_app** in `ig_actions.p4` for the DUT output port.
- Edit `control.py` to update the list of QCM recirculation ports used by the cryptographic pipeline.
- Edit `pktgen.py` only if the PktGen source port changes. For Tofino-1 pipe 0, the default PktGen source devport is usually 68.
- Edit `monitor_egress_port.p4` with the DUT devport if you want to collect traffic metrics directly from the data plane.

**2. Set the environment variables.**

The SDE environment variables are usually set from the SDE directory with:
```bash
. ~/user/tools/set_sde.bash`
```
**3. Run:**

The `exec.sh` script simplifies the execution workflow by automating:
- P4 compilation,
- table entry configuration,
- port configuration,
- PktGen application setup, and
- some commands in the Tofino port manager.

*You must explicitly provide the request data size*
```bash
./exec.sh 64
./exec.sh 128
./exec.sh 192
./exec.sh 256
./exec.sh 320
./exec.sh 384
```
**4. Monitor (Optional)**

In a parallel terminal, run:

```bash
python3 monitor_egress_port.py
```

# License
This program is released under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html).

# Contribuitors

- Filipo G. Costa, Federal University Estadual de Campinas (UNICAMP), Brazil
- Francisco G. Vogt, University Estadual de Campinas (UNICAMP), Brazil
- Fabricio Rodrıguez Cesen, Telefonica Research, Spain
- Marcelo Caggiani Luizelli, Federal University of Pampa (UNIPAMPA), Brazil
- Christian Esteve Rothenberg, University Estadual de Campinas (UNICAMP), Brazil
