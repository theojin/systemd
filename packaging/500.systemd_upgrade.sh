#!/bin/sh

#-----------------------------------------------#
# systemd patch for upgrade (2.4 -> 3.0) #
#-----------------------------------------------#

# Macro
PATH=/bin:/usr/bin:/sbin:/usr/sbin
WTMP_DIR=/var/log/wtmp
SYSTEMD_DIR=/var/lib/systemd

# set smack rule
chsmack -a "System" $WTMP_DIR
chsmack -a "System" $SYSTEMD_DIR
