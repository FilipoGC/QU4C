#kill any old process running
killall bf_switchd
killall run_switchd


#load module if not loaded
bf_kdrv_mod_load $SDE_INSTALL

python3 generate_params.py "$1"

DATA_BLOCKS=$(python3 -c 'from param import DATA_BLOCKS; print(DATA_BLOCKS)')
DATA_SIZE=$(python3 -c 'from param import DATA_SIZE; print(DATA_SIZE)')

echo "==== Running QU4C: DATA_BLOCKS=${DATA_BLOCKS}, data_size=${DATA_SIZE}B ===="

# compile p4
"$SDE"/../tools/p4_build.sh p4/chacha.p4

# start switch
"$SDE"/run_switchd.sh -p chacha > switchd.log 2>&1 &
sleep 20

# configure ports
"$SDE"/run_bfshell.sh -f portConfig.txt

#config tables that use bfshell API
"$SDE"/run_bfshell.sh -b auxTables.py

sleep 2

#install BFRT rules for recirculation selection
python3 control.py
echo "sleep 30"
sleep 30

#initialize packet generation. pktgen.py reads the values from param.py.
python3 pktgen.py

#show rates/useful view commands
"$SDE"/run_bfshell.sh -f view

killall bf_switchd
