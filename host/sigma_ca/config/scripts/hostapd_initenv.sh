#!/bin/sh

conf_default_path=/etc/default

if [ -e "${conf_default_path}/nvram" ]; then
	. "${conf_default_path}/nvram"
fi

hostapd_exec=/usr/sbin/hostapd
hostapd_cli_exec=/usr/sbin/hostapd_cli

# first parameter is name of configuration
conf_name=$1

