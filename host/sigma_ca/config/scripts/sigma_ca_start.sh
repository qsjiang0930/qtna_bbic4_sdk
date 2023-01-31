#!/bin/sh

. "$(dirname $(readlink -f "$0"))/sigma_ca_initenv.sh" $@

if [ -d "${nvram_path}/default" ]; then
	defaults_path=${nvram_path}/default
else
	defaults_path=${conf_default_path}
fi

if [ ! -f "${defaults_path}/sigma_ca.${conf_name}" ]; then
	echo "error: the [${defaults_path}/sigma_ca.${conf_name}] configuration does not exist"
	exit 1
fi

. "${defaults_path}/sigma_ca.${conf_name}"

if [ -z "${ca_ipaddr}" ] || [ -z "${ca_port}" ] || [ -z "${dut_addr}" ]; then
	echo "error: sigma_ca configuration is not properly defined"
	exit 1
fi

# DUT address can be equal to QLINK configuration from hostapd
if [ "${dut_addr}" = "qlink" ]; then
	# load hostapd config
	if [ ! -f "${defaults_path}/hostapd.${conf_name}" ]; then
		echo "error: the [default/hostapd.${conf_name}] configuration does not exist"
		exit 1
	fi

	. "${defaults_path}/hostapd.${conf_name}"

	if [ -z "${qlink_iface}" ] || [ -z "${qlink_server_addr}" ]; then
		echo "error: qlink configuration is not defined"
		exit 1
	fi

	dut_addr="raw,${qlink_iface},${qlink_server_addr}"
fi

${sigma_ca_exec} -b -a ${ca_ipaddr} -p ${ca_port} -d ${dut_addr} -c ${conf_name} -i ${conf_images_path}
