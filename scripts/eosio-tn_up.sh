#!/bin/bash
#
# eosio-tn_up is a helper script used to start a node that was previously stopped.
# It is not intended to be run stand-alone; it is a companion to the
# eosio-tn_bounce.sh and eosio-tn_roll.sh scripts.

connected="0"

rundir=programs/nodeos
prog=nodeos

# Quote any args that are "*", so they are not expanded
qargs=`echo "$*" | sed -e 's/ \* / "*" /' -e 's/ \*$/ "*"/'`

if [ "$PWD" != "$EOSIO_HOME" ]; then
    echo $0 must only be run from $EOSIO_HOME
    exit -1
fi

if [ ! -e $rundir/$prog ]; then
    echo unable to locate binary for nodeos
    exit -1
fi

if [ -z "$EOSIO_NODE" ]; then
    echo data directory not set
    exit -1
fi

pbft_db_dir=var/lib/node_$EOSIO_NODE
now=`date +'%Y_%m_%d_%H_%M_%S'`
log=stderr.$now.txt
touch $pbft_db_dir/$log
rm $pbft_db_dir/stderr.txt
ln -s $log $pbft_db_dir/stderr.txt

relaunch() {
    echo "$rundir/$prog $qargs $* --data-dir $pbft_db_dir --config-dir etc/eosio/node_$EOSIO_NODE > $pbft_db_dir/stdout.txt  2>> $pbft_db_dir/$log "
    nohup $rundir/$prog $qargs $* --data-dir $pbft_db_dir --config-dir etc/eosio/node_$EOSIO_NODE > $pbft_db_dir/stdout.txt  2>> $pbft_db_dir/$log &
    pid=$!
    echo pid = $pid
    echo $pid > $pbft_db_dir/$prog.pid

    for (( a = 10; $a; a = $(($a - 1)) )); do
        echo checking viability pass $((11 - $a))
        sleep 2
        running=$(pgrep $prog | grep -c $pid)
        echo running = $running
        if [ -z "$running" ]; then
            break;
        fi
        connected=`grep -c "net_plugin.cpp:.*connection" $pbft_db_dir/$log`
        if [ "$connected" -ne 0 ]; then
            break;
        fi
    done
}

if [ -z "$EOSIO_LEVEL" ]; then
    echo starting with no modifiers
    relaunch
    if [ "$connected" -eq 0 ]; then
        EOSIO_LEVEL=replay
    else
        exit 0
    fi
fi

if [ "$EOSIO_LEVEL" == replay ]; then
    echo starting with replay
    relaunch --hard-replay-blockchain
    if [  "$connected" -eq 0 ]; then
        EOSIO_LEVEL=resync
    else
        exit 0
    fi
fi
if [ "$EOSIO_LEVEL" == resync ]; then
    echo starting with delete-all-blocks
    relaunch --delete-all-blocks
fi
