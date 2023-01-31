#!/bin/sh

. "$(dirname $(readlink -f "$0"))/hostapd_initenv.sh" $@

if [ -d "${nvram_path}/default" ]; then
	defaults_path=${nvram_path}/default
else
	defaults_path=${conf_default_path}
fi

if [ ! -f "${defaults_path}/hostapd.conf.templ" ]; then
	echo "error: the [${defaults_path}/hostapd.conf.templ] template does not exist"
	exit 1
fi

if [ ! -f "${defaults_path}/hostapd.${conf_name}" ]; then
	echo "error: the [${defaults_path}/hostapd.${conf_name}] configuration does not exist"
	exit 1
fi

# load hostapd parameters
. "${defaults_path}/hostapd.${conf_name}"

if [ -z "${qlink_iface}" ] || [ -z "${qlink_server_addr}" ]; then
	echo "error: qlink configuration is not defined"
	exit 1
fi

if [ -z "${wifi_iface}" ] || [ -z "${wifi_hw_mode}" ]; then
	echo "error: wifi configuration is not defined"
	exit 1
fi

if [ ! -d "${nvram_path}/current" ]; then
	echo "error: the [${nvram_path}/current] does not exist"
	exit 1
fi

if [ -z "${wifi_ssid}" ]; then
	wifi_ssid="QTN-AP-$(basename $(mktemp -u))"
fi

if [ -z "${wifi_passphrase}" ]; then
	wifi_passphrase="pswd$(basename $(mktemp -u))"
fi

hostapd_temp_config=$(mktemp)

sed -e "s/@QLINK_IFACE@/${qlink_iface}/g" \
    -e "s/@QLINK_SERVER_ADDR@/${qlink_server_addr}/g" \
    -e "s/@WIFI_IFACE@/${wifi_iface}/g" \
    -e "s/@WIFI_HW_MODE@/${wifi_hw_mode}/g" \
    -e "s/@CONF_NAME@/${conf_name}/g" \
    -e "s/@SSID@/${wifi_ssid}/g" \
    -e "s/@PASSPHRASE@/${wifi_passphrase}/g" \
    "${defaults_path}/hostapd.conf.templ" > ${hostapd_temp_config}

# overwrite the current configuration
mv -f ${hostapd_temp_config} "${nvram_path}/current/hostapd.conf.${conf_name}"
