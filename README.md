# QU4C: Towards Reproducing QUIC Traffic on a P4-Based Programmable Switch

QU4C is based on the original ChaCha-Tofino project  
(https://github.com/Hasegawa-Laboratory/ChaCha-Tofino).

In this work, we extend the original implementation to parse and process emulated QUIC packets. The current version still includes hardcoded parameters, so users may need to adapt the port configuration to match their Tofino environment.

⚠️ This project is still under development and currently contains preliminary results and ongoing implementation efforts.

# Usage
> We tested this project with Intel BF-SDE versions 9.12 and 9.13.2.

1. Update `configPorts.txt` with:
   - the output port,
   - the recirculation port for `PktGen`, and
   - the recirculation ports used by the cipher.

2. Update `control.py` accordingly, making sure the same recirculation ports are configured there as well.

3. Set the required environment variables.

4. Run:

```bash
./exec.sh
