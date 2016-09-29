#!/bin/sh

PATH=/bin:/usr/bin:/sbin:/usr/sbin

systemctl --user import-environment DISPLAY XAUTHORITY
