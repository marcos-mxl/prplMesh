#!/bin/sh
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# Copyright (c) 2019 Tomer Eliyahu (Intel)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

SIG_TERM=-15
SIG_KILL=-9

dbg() {
    [ "$VERBOSE" = "true" ] && echo "$@"
}

err() {
    printf '\033[1;31m'"$@\n"'\033[0m'
}

success() {
    printf '\033[1;32m'"$@\n"'\033[0m'
}

run() {
    dbg "$*"
    "$@" || exit $?
}

killall_program() {
    PROGRAM_NAME=$1
    if [ "$#" -eq 2 ]; then
        KILL_SIG=$2
    else
        KILL_SIG=$SIG_KILL
    fi
    for PID in $(ps -ef | grep $PROGRAM_NAME | grep -v grep | grep -v ${0} | grep -v vi | grep -v tail | awk '{print $2}'); do
        echo "kill $KILL_SIG $PID $PROGRAM_NAME";
        kill $KILL_SIG $PID > /dev/null 2>&1;
    done
}

prplmesh_platform_db_init() {
    management_mode=${1-Multi-AP-Controller-and-Agent}
    operating_mode=${2-Gateway}

    mkdir -p /tmp/
    {
        echo "management_mode=${management_mode}"
        echo "operating_mode=${operating_mode}"
        echo "wired_backhaul=1"
    } > /tmp/prplmesh_platform_db
}

is_wireless_iface() {
        iwconfig "$1" > /dev/null 2>&1 
}

platform_init_certification() {
    echo "platform certification mode init..."
    base_mac=44:55:66:77
    bridge_ip=192.168.250.140
    
    run ip link add          br-lan   address "${base_mac}:00:00" type bridge
    run ip link add          wlan0    address "${base_mac}:00:10" type dummy
    run ip link add          wlan2    address "${base_mac}:00:20" type dummy
    run ip link set      dev wlan0    master br-lan
    run ip link set      dev wlan2    master br-lan
    run ip link set      dev wlan0    up
    run ip link set      dev wlan2    up
    for iface in $(ifconfig | cut -d ' ' -f1| tr ':' '\n' | awk NF)
    do
            [ "$iface" = "lo" ] && continue
            is_wireless_iface "$iface" && continue 
            run ip link set dev "$iface" master br-lan
            run ifconfig "$iface" 0.0.0.0
    done
    run ifconfig br-lan "$bridge_ip" up
}

platform_deinit_certification() {
    echo "platform certification mode de-init..."
    ip link set br-lan down
    brctl delbr br-lan
    ip link set wlan0 down
    ip link set wlan2 down
    ip link del wlan0
    ip link del wlan2
    echo "Done"
}

platform_init_dummy() {
    echo "platform dummy mode init..."
    run ip link add wlan0 type dummy
    run ip link add wlan2 type dummy
    run ip link add sim-eth0 type dummy
    run brctl addbr br-lan
    run brctl addif br-lan sim-eth0
    run brctl addif br-lan wlan0
    run brctl addif br-lan wlan2
    run ip link set sim-eth0 up
    run ip link set wlan0 up
    run ip link set wlan2 up
    run ip link set br-lan up
    echo "Done"
}

platform_deinit_dummy() {
    echo "platform dummy mode de-init..."
    ip link set br-lan down
    brctl delbr br-lan
    ip link set sim-eth0 down
    ip link set wlan0 down
    ip link set wlan2 down
    ip link del sim-eth0
    ip link del wlan0
    ip link del wlan2
    echo "Done"
}

prplmesh_framework_init() {
    echo "prplmesh_framework_init - starting local_bus and ieee1905_transport processes..."
    /home/prplmesh/work/dev1/build/install/bin/local_bus &
    /home/prplmesh/work/dev1/build/install/bin/ieee1905_transport &
}

prplmesh_framework_deinit() {
    echo "prplmesh_framework_init - killing local_bus and ieee1905_transport processes..."
    killall_program local_bus
    killall_program ieee1905_transport
}

prplmesh_controller_start() {
    echo "prplmesh_controller_start - start beerocks_controller process..."
    /home/prplmesh/work/dev1/build/install/bin/beerocks_controller &
}

prplmesh_controller_stop() {
    echo "prplmesh_controller_stop - stopping beerocks_controller process..."
    killall_program beerocks_controller
}

prplmesh_agent_start() {
    echo "prplmesh_agent_start - start beerocks_agent process..."
    /home/prplmesh/work/dev1/build/install/bin/beerocks_agent &
}

prplmesh_agent_stop() {
    echo "prplmesh_agent_stop - stopping beerocks_agent process..."
    killall_program beerocks_agent
}

start_function() {
    echo "$0: start"
    [ `id -u` -ne 0 ] && echo "$0: warning - this commands needs root privileges so might not work (are you root?)"

    #[ "DUMMY" = "DUMMY" -a "$PLATFORM_INIT" = "true" ] && platform_init_dummy
    platform_init_certification
    [ "LOCAL_BUS" = "LOCAL_BUS" ] && prplmesh_framework_init
    case "$PRPLMESH_MODE" in
        CA | ca)
            prplmesh_platform_db_init "Multi-AP-Controller-and-Agent"
            prplmesh_controller_start
            prplmesh_agent_start
            ;;
        C | c)
            prplmesh_platform_db_init "Multi-AP-Controller"
            prplmesh_controller_start
            ;;
        A | a)
            prplmesh_platform_db_init "Multi-AP-Agent" "WDS-Repeater"
            prplmesh_agent_start
            ;;
        * ) err "unsupported mode: $PRPLMESH_MODE"; usage; exit 1 ;;
    esac
}

stop_function() {
    echo "$0: stop"
    [ `id -u` -ne 0 ] && echo "$0: warning - this commands needs root privileges so might not work (are you root?)"

    #[ "DUMMY" = "DUMMY" -a "$PLATFORM_INIT" = "true" ] && platform_deinit_dummy
    platform_deinit_certification
    [ "LOCAL_BUS" = "LOCAL_BUS" ] && prplmesh_framework_deinit
    [ "$PRPLMESH_MODE" = "CA" -o "$PRPLMESH_MODE" = "C" ] && prplmesh_controller_stop
    [ "$PRPLMESH_MODE" = "CA" -o "$PRPLMESH_MODE" = "A" ] && prplmesh_agent_stop
}

main_agent_operational() {
    ps -aux | grep beerocks_agent | grep -v wlan | grep -v grep > /dev/null 2>&1 || return 1
    grep -q 'CONNECTED --> OPERATIONAL' "$1/beerocks_agent.log"
}

radio_agent_operational() {
    ps -aux | grep beerocks_agent | grep $2 | grep -v grep > /dev/null 2>&1 || return 1
    grep -q 'CSA' "$1/beerocks_agent_$2.log"
}

report() {
    msg="$1"; shift
    if "$@"; then
        success "OK $msg"
    else
        err "FAIL $msg"
        error=1
    fi
}

status_function() {
    echo "$0: status"

    ps -aux | grep beerocks | grep -v grep
    ps -aux | grep ieee1905_transport | grep -v grep
    ps -aux | grep local_bus | grep -v grep

    # check for operational status
    LOGS_PATH=/tmp/prplmesh/beerocks/logs/

    error=0
    report "Main agent operational" main_agent_operational $LOGS_PATH
    report "wlan0 radio agent operational" radio_agent_operational $LOGS_PATH wlan0
    report "wlan2 radio agent operational" radio_agent_operational $LOGS_PATH wlan2

    [ "$VERBOSE" = "true" -a $error = 1 ] && {
        cat $LOGS_PATH/beerocks_agent.log
        cat $LOGS_PATH/beerocks_agent_wlan0.log
        cat $LOGS_PATH/beerocks_agent_wlan2.log
    }

    return $error
}

usage() {
    echo "usage: $(basename $0) {start|stop|restart|status} [-hvsm]"
}

main() {
    OPTS=`getopt -o 'hvm:s' --long verbose,help,mode:skip-platform -n 'parse-options' -- "$@"`

    if [ $? != 0 ] ; then err "Failed parsing options." >&2 ; usage; exit 1 ; fi

    eval set -- "$OPTS"

    while true; do
        case "$1" in
            -v | --verbose)       VERBOSE=true; shift ;;
            -h | --help)          usage; exit 0; shift ;;
            -m | --mode)          PRPLMESH_MODE="$2"; shift; shift ;;
            -s | --skip-platform) PLATFORM_INIT=false; shift ;;
            -- ) shift; break ;;
            * ) err "unsupported argument $1"; usage; exit 1 ;;
        esac
    done

    dbg VERBOSE=$VERBOSE
    dbg PLATFORM_INIT=$PLATFORM_INIT

    case $1 in
        "start")
            start_function
            ;;
        "stop")
            stop_function
            ;;
        "restart")
            stop_function
            start_function
            ;;
        "status")
            status_function
            ;;
        *)
            err "unsupported argument \"$1\""; usage; exit 1 ;;
    esac
}

VERBOSE=false
PLATFORM_INIT=true
PRPLMESH_MODE="CA" # CA = Controller & Agent, A = Agent only, C = Controller only

main $@
