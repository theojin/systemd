#!/bin/sh

PATH=/bin:/usr/bin:/sbin:/usr/sbin

systemctl --user import-environment DISPLAY XAUTHORITY

if which dbus-update-activation-environment >/dev/null 2>&1; then
        dbus-update-activation-environment DISPLAY XAUTHORITY
fi
