#!/bin/sh

. "$(dirname $(readlink -f "$0"))/hostapd_initenv.sh" $@

check_period=5

# check the configuration
if [ -d "${nvram_path}/default" ]; then
	defaults_path=${nvram_path}/default
else
	defaults_path=${conf_default_path}
fi

if [ ! -f "${defaults_path}/hostapd.${conf_name}" ]; then
	echo "error: the [${defaults_path}/hostapd.${conf_name}] configuration does not exist"
	exit 1
fi

while true; do
	if [ ! -f /tmp/hostapd.${conf_name}.pid ] && [ ! -f /tmp/hostapd.${conf_name}.running ]; then
		hostapd_start.sh ${conf_name}
	fi
	sleep ${check_period}
done

