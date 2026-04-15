#kill any old process running
killall bf_switchd
killall run_switchd


#load module if not loaded
bf_kdrv_mod_load $SDE_INSTALL

$SDE/../tools/p4_build.sh p4/chacha.p4

# start switch
$SDE/run_switchd.sh -p chacha > switchd.log 2>&1 &
sleep 20

# configure ports
/$SDE/run_bfshell.sh -f portConfig.txt

#Config Tables
/$SDE/run_bfshell.sh -b auxTables.py

sleep 2

#Install RULES
nohup python3 control.py

sleep 5

#Initialize Generation
python3 pktgen.py

#show
/$SDE/run_bfshell.sh -f view
