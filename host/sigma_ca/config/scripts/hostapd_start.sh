#!/bin/sh

. "$(dirname $(readlink -f "$0"))/hostapd_initenv.sh" $@

# check the current configuration
current_config=${nvram_path}/current/hostapd.conf.${conf_name}

if [ ! -e "${current_config}" ]; then
	if ! hostapd_make_default_config.sh "${conf_name}"; then
		echo "error: unable to create current configuration"
		exit 1
	fi
fi

if [ ! -e "${current_config}" ]; then
	echo "error: the [${current_config}] does not exist"
	exit 1
fi

${hostapd_exec} -P /tmp/hostapd.${conf_name}.pid -B ${current_config}
