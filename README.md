# QU4C: Towards Reproducing QUIC Traffic on a P4-Based Programmable Switch

QU4C is based on the original ChaCha-Tofino project  
(https://github.com/Hasegawa-Laboratory/ChaCha-Tofino).

In this work, we extend the original implementation to parse and process emulated QUIC packets. The current version still includes hardcoded parameters, so users may need to adapt the port configuration to match their Tofino environment.

⚠️ This project is still under development and currently contains preliminary results and ongoing implementation efforts.

# Usage
> We tested this project with Intel BF-SDE versions 9.12.0 and 9.13.2.

1. Update `configPorts.txt` and `auxTables.py` with:
   - the output (server) port,
   - client port,
   - the recirculation port for `PktGen`, and
   - the recirculation ports used by the cipher.

2. Update `control.py` accordingly with recirculation ports of cipher.

3. Set the environment variables.

4. Run:

The `exec.sh` script simplifies the execution workflow by automating:
- P4 compilation,
- table entries configuration,
- port configuration,
- `PktGen` application setup, and
- some commands in the Tofino port manager.
```bash
./exec.sh
```
# License
This program is released under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html).

# Contribuitors

- Filipo G. Costa, Federal University of Pampa (UNICAMP), Brazil
- Francisco G. Vogt, University of Campinas (UNICAMP), Brazil
- Fabricio Rodrıguez Cesen, University of Campinas (UNICAMP), Brazil
- Marcelo Caggiani Luizelli, Federal University of Pampa (UNIPAMPA), Brazil
- Christian Esteve Rothenberg, University of Campinas (UNICAMP), Brazil
