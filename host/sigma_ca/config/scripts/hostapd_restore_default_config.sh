#!/bin/sh

. "$(dirname $(readlink -f "$0"))/hostapd_initenv.sh" $@

# WAR: restart hostapd for updating configuration

touch /tmp/hostapd.${conf_name}.running

hostapd_stop.sh ${conf_name}

sleep 2

if ! hostapd_make_default_config.sh $@; then
	rm -f /tmp/hostapd.${conf_name}.running
	echo "error: unable to make default configuration"
	exit 1
fi

hostapd_start.sh ${conf_name}

sleep 1

rm -f /tmp/hostapd.${conf_name}.running

# TODO: uncomment this code after fix the "reconfigure" command
#
#hostapd_ctrl_iface="/var/run/hostapd"
#
#if ! ${hostapd_cli_exec} -p ${hostapd_ctrl_iface} reconfigure; then
#	echo "error: unable to reconfigure hostapd"
#	exit 1
#fi
#
