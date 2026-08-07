#!/bin/sh /etc/rc.common
# Benign OpenWrt init script — no implant paths, no rctl protocol.
START=95
start() {
    logger "starting network watchdog (monitors kworker load)"
    /usr/sbin/netwatchd --interval 35 &
}
