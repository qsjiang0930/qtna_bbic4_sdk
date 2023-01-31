#!/bin/sh

. "$(dirname $(readlink -f "$0"))/hostapd_initenv.sh" $@

if [ -e "/tmp/hostapd.${conf_name}.pid" ]; then
	pid=$(cat "/tmp/hostapd.${conf_name}.pid")
	kill $pid
fi
