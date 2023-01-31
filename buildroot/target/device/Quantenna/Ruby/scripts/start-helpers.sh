#!/bin/sh

base_persistent_files="/mnt/jffs2"
base_default_conf_file="/etc"
hostapd_pid_file="/var/run/hostapd.pid"

. $base_scripts/wireless_conf_params

# This file is created at compile time if stateless mode is enabled
# (i.e. when BR2_TARGET_RUBY_STATELESS=y).
if [ -f $base_scripts/build_config ]; then
	. $base_scripts/build_config
fi

stateless=`grep -o 'stateless=[0-9]*' /proc/cmdline | cut -d= -f2`

if [ "${STATELESS}" = "" ] && [ "$stateless" = "1" ]; then
	STATELESS=y
	export STATELESS
fi

wps_push_button_gpio=`get_wifi_config wifi0 wps_push_button_gpio`

if [ $? -ne 0 ]
then
	wps_push_button_gpio=4
fi

reset_device_gpio=5
rfenable_gpio=12

if [ -e /proc/amber ]
then
	wps_push_button_gpio=1
	rfenable_gpio=2
fi

default_ipaddr_ap=192.168.1.100
default_ipaddr_sta=192.168.1.200
default_ipaddr_rc=169.254.1.1
default_ipaddr_ep=169.254.1.2
init_ipaddrs_file=$base_persistent_files/init-ipaddrs

#This option is only used for Topaz PCIe EP boards
en_tqe_sem=1

get_configuration_ip() {
	get_bootval ipaddr
}

get_param_from_file()
{
	param_name=$1
	file_name=$2
	sep=$3
	awk -F"$sep" "
		/$param_name/ {
			print \$2;
			exit
		}" $file_name
}

get_rc_init_ipaddr()
{
	local ipaddr
	if [ -f $init_ipaddrs_file ]
	then
		ipaddr=$(get_param_from_file rc-init $init_ipaddrs_file ':')
	fi
	if [ -z $ipaddr ]
	then
		ipaddr=$default_ipaddr_rc
	fi
	echo $ipaddr
}

get_ep_init_ipaddr()
{
	local ipaddr
	if [ -f $init_ipaddrs_file ]
	then
		ipaddr=$(get_param_from_file ep-init $init_ipaddrs_file ':')
	fi
	if [ -z $ipaddr ]
	then
		ipaddr=$default_ipaddr_ep
	fi
	echo $ipaddr
}

echo_with_logging()
{
    logger -- $@
    echo $@
}

hex2dec()
{
    hexval=0x$(echo $1 | sed 's%0x%%')
    let decval=$hexval
    echo $decval
}

get_board_name()
{
	get_board_config name
}

list_contains()
{
	item=$1
	shift
	for i in $@
	do
		if [ "$i" = "$item" ]
		then
			return 0
		fi
	done
	return 1
}

get_hw_config_id()
{
	get_board_config board_id
}

hw_config_id_in_list()
{
	hw_config_id=$(get_hw_config_id)
	if [ $? -eq 0 ] ; then
		if list_contains $hw_config_id $@ ; then
			return 0
		else
			return 1
		fi
	else
		echo Error getting hw_config_id
	fi
	return 1
}

get_security_path()
{
	security_file_path=`call_qcsapi -u get_file_path security`
	error_check=`echo $security_file_path | cut -b 1-13`
	if [ "$error_check" = "QCS API error" ]; then
		echo_with_logging "Cannot get path to hostapd.conf and wpa_supplicant.conf."
		echo_with_logging "Using default of ${base_persistent_files}, but the web-base GUI likely will fail."
		security_file_path=${base_persistent_files}
	fi
}

check_default_security_files()
{
	get_security_path

	wifi_mode=$1
	force_restore=$2

	if [ "$wifi_mode" = "ap" ] || [ "$wifi_mode" = "repeater" ]; then
		security_config_file=${security_file_path}/hostapd.conf
		if [ ! -f ${security_config_file} ] || [ $force_restore -eq 1 ]; then
			cp $base_scripts/hostapd.conf ${security_config_file}
		fi
	else
		security_config_file=${security_file_path}/wpa_supplicant.conf
		if [ ! -f ${security_config_file} ] || [ $force_restore -eq 1 ]; then
			cp $base_scripts/wpa_supplicant.conf ${security_config_file}
		fi

		if [ ! -f ${security_file_path}/wpa_supplicant.conf.pp ]
		then
			touch ${security_file_path}/wpa_supplicant.conf.pp
		fi
	fi
}

start_security_daemon()
{
	wifi_mode=$1
	wifi_repeater=$2

	check_default_security_files "$wifi_mode" 0
	check_wps "$security_config_file" "$wifi_mode"

        # disable ap pin in all BSSes
        local_wps_ap_cfg=`get_wifi_config wifi0 wps_ap_cfg`
	orig_wps_ap_cfg=`cat $security_config_file |grep ap_setup_locked`
	orig_wps_ap_cfg=${orig_wps_ap_cfg#ap_setup_locked=}
        if [ "$wifi_mode" = "ap" ]; then
               if [ "$local_wps_ap_cfg" = "0" ]; then
                      if [ "$orig_wps_ap_cfg" != "1" ]; then
                             echo "Disable ap pin setup in all BSSes"
                             sed -i "s;\(ap_setup_locked\)=.*$;\1=1;g" $security_config_file
                      fi
               else
                      if [ "$orig_wps_ap_cfg" != "0" ]; then
                             echo "Enable ap pin setup in all BSSes"
                             sed -i "s;\(ap_setup_locked\)=.*$;\1=0;g" $security_config_file
                      fi
               fi
        fi

	if [ "$wifi_mode" = "ap" ]; then
		if pidof hostapd > /dev/null; then
			return
		fi
		qlink=`get_wifi_config wifi0 qlink`
		if [ $? -ne 0 -o "$qlink" = "0" -o "$wifi_repeater" = "1" ]; then
			if [ "$wifi_repeater" = "1" ]; then
				cmd="hostapd -P $hostapd_pid_file -B $security_config_file -r"
			else
				cmd="hostapd -P $hostapd_pid_file -B $security_config_file"
			fi
		elif [ "$qlink" = "1" -o "$qlink" = "auto"  ]; then
			cmd="/usr/sbin/hostapd-proxy/hostapd -P $hostapd_pid_file -B $security_config_file"
		else
			cmd="/usr/sbin/hostapd-proxy/hostapd -P $hostapd_pid_file -I $qlink -B $security_config_file"
		fi
	else
		if pidof wpa_supplicant > /dev/null; then
			return
		fi
		cmd="wpa_supplicant -B -q -iwifi0 -bbr0 -Dmadwifi -c $security_config_file"
	fi

	$base_scripts/launch start "$cmd"
}

check_wireless_config()
{
	local params_must_have="mode region"
	local config_file=$1

	for param in $params_must_have; do
		val=`get_wifi_config wifi0 $param $config_file`
		if [ $? -ne 0 ] || [ "$val" = "" ]; then
			return 0
		fi
	done

	return 1
}

wireless_conf_bak=wireless_conf.bak
backup_wireless_config()
{
	echo_with_logging "Backing up wireless_conf.txt..."
	cp ${base_persistent_files}/wireless_conf.txt ${base_persistent_files}/${wireless_conf_bak}
}

restore_wireless_config_from_backup()
{
	echo_with_logging "Restoring wireless_conf.txt from backup..."
	cp ${base_persistent_files}/${wireless_conf_bak} ${base_persistent_files}/wireless_conf.txt
}

check_wireless_config_exists()
{
	config_path=${base_persistent_files}/wireless_conf.txt
	$base_scripts/update_config_utility check ${config_path}

	if [ $? -ne 0 ]; then
		echo_with_logging "${config_path} not found.  Creating a default conf file"
		restore_wireless_conf
	elif check_wireless_config wireless_conf.txt; then
		if ! check_wireless_config ${wireless_conf_bak}; then
			restore_wireless_config_from_backup
		else
			restore_wireless_conf
		fi
	fi
}

free_boot_memory()
{
    # Firmwares are loaded, and can't be reloaded.
    # Let's delete all firmwares as they occupy RAM (tmpfs).
    ls /etc/firmware/*.bin | grep -v u-boot.bin | xargs rm -f
}

ipaddr_process() {
	if [ -f /mnt/jffs2/ipaddr ]
	then
		ipaddress=`cat /mnt/jffs2/ipaddr`
	fi

	if [ -f /mnt/jffs2/netmask ]
	then
		netmask_addr=`cat /mnt/jffs2/netmask`
	fi

	if [ "$ipaddress" == "" ] ; then
		cat /proc/cmdline | grep 'ip=' | sed 's/\(.*\)ip=\(.*\)/\2/' | \
			awk '{ print $1 }' > /etc/ipaddr
		if [ -s /etc/ipaddr ]
		then
			ipaddress=`cat /etc/ipaddr`
		fi
	fi

	if [ "$ipaddress" == "" ] ; then
		get_bootval ipaddr > /etc/ipaddr
		if [ -s /etc/ipaddr ]
		then
			ipaddress=`cat /etc/ipaddr`
		fi
	fi

	if [ "$ipaddress" == "" ] ; then
		#assign a default IP address to br0 ,avoid that wireless interface can't be up
		wifi_mode=`/scripts/get_wifi_config wifi0 mode`
		if [ $wifi_mode == "ap" ] ; then
			ipaddress="192.168.1.100"
		else
			ipaddress="192.168.1.200"
		fi
	fi

	sed -i "s/192.168.0.10/$ipaddress/g" /etc/network/interfaces
	echo "Using IP address $ipaddress"

	if [ "$netmask_addr" != "" ] ; then
		sed -i "s/255.255.255.0/$netmask_addr/g" /etc/network/interfaces
		echo "Using netmask $netmask_addr"
	else
		echo "Netmask is not set"
	fi
}

gw_dns_process()
{
	if [ -f /mnt/jffs2/gateway ]
	then
		gw=`cat /mnt/jffs2/gateway`
	fi

	if [ "$gw" != "" ]; then
		route add default gw $gw
	fi
}

wifi_macaddr_configure()
{
	mac0addr="0"
	local qlink=$(get_bootval qlink)

	if [ "${STATELESS}" = "y" ] || [ $qlink != 0 ]
	then
		mac0addr=`${base_scripts}/get_bootval wifi_mac_addr`
	fi

	if [ "${mac0addr}" = "0" -a -f ${base_persistent_files}/wifi_mac_addrs ]
	then
		mac0addr=`cat ${base_persistent_files}/wifi_mac_addrs | head -1`
	fi

	if [ "${mac0addr}" = "0" ]
	then
		mac0addrlow=`dd if=/dev/urandom count=1 2>/dev/null | md5sum | \
			sed 's/^\(..\)\(..\)\(..\).*$/\1:\2:\3/'`
		mac0addr="00:26:86:${mac0addrlow}"
		echo "Warning: Setting randomized MAC address! " $mac0addr
		echo $mac0addr > ${base_persistent_files}/wifi_mac_addrs
	fi
}

is_2_4_ghz_mode()
{
	mode=$1
	case "$mode" in
	11ng | 11b | 11g)
		echo "1"
		return
		;;
	esac
	echo "0"
}

is_channel_in_2_4_ghz_band()
{
	chan=$1
	if [ $chan -ge 1 ] && [ $chan -le 14 ]; then
		echo "1"
	else
		echo "0"
	fi
}

is_platform_dual_band()
{
	platform_name=$1
	if [ "$platform_name" = "QTP952_DS1_MS" ] || \
		[ "$platform_name" = "QHS952_DS1" ] || \
		[ "$platform_name" = "QHS842_DBS1" ] || \
		[ "$platform_name" = "QHS842_DS1" ] || \
		[ "$platform_name" = "QHS842_DS2" ] || \
		[ "$platform_name" = "QTM942_DS1_MS" ] || \
		[ "$platform_name" = "QTM942_DS2_MS" ]; then
		return 0
	fi

	return 1
}

is_platform_def_mode_station()
{
	board_name=$1
	if [ "$board_name" = "QHS842_DBS1" ] || \
		[ "$board_name" = "QHS842_DS1" ] || \
		[ "$board_name" = "QHS842_DS2" ] || \
		[ "$board_name" = "QTM840_5S1_MAC" ] || \
		[ "$board_name" = "QTM942_DS1_MS" ] || \
		[ "$board_name" = "QTM942_DS2_MS" ] || \
		[ "$board_name" = "QHS952_DS1" ] || \
		[ "$board_name" = "QTP952_DS1_MS" ]; then
		return 0
	fi

	return 1
}

is_platform_bf_disabled()
{
	local board_name=$1

	if [ "$board_name" = "QTM942_DS1_MS" ] || \
		[ "$board_name" = "QTM942_DS2_MS" ] || \
		[ "$board_name" = "QHS952_DS1" ] || \
		[ "$board_name" = "QTP952_DS1_MS" ]; then
		return 0
	fi
	return 1
}

is_platform_bf_disable_in_default_config()
{
	local board_name=$1

	if is_platform_bf_disabled $board_name; then
		return 0
	fi
	if [ "$board_name" = "QTM840_5S1_MAC" ]; then
		return 0
	fi
	return 1
}

check_default_bsad_config_file()
{
	local default_config
	local bsad_config_filename=bsa_conf.txt

	get_security_path
	bsad_config_file="${security_file_path}/${bsad_config_filename}"
	default_bsad_config="/etc/${bsad_config_filename}"

	if [ ! -f "$bsad_config_file" ]; then
		echo "Restoring $bsad_config_file from $default_bsad_config"
		cp "$default_bsad_config" "$bsad_config_file"
		chmod 664 "$bsad_config_file"
	fi
}

autochan_param_list="
	cci_instnt
	aci_instnt
	cci_longterm
	aci_longterm
	range_cost
	dfs_cost
	min_cci_rssi
	maxbw_minbenefit
	dense_cci_span
	dbg_level"

autochan_parameters_config()
{
	iface=$1

	for param in $autochan_param_list
	do
		value=`${base_scripts}/get_autochan_config $iface $param`
		if [ $? -eq 0 ]
		then
			call_qcsapi -u -q set_autochan_params $iface $param $value
			if [ $? -ne 0 ]
			then
				echo "Error: fail to set autochan parameter $param with value $value"
			fi
		fi
	done
}

is_platform_rgmii()
{
	platform_file=$base_scripts/platform_id
	if [ -f $platform_file ]; then
		platform_id=`cat $platform_file`
	else
		platform_id=0
	fi

	if [ "$platform_id" = "413" -o "$platform_id" = "432" -o "$platform_id" = "463" ]; then
		return 0
	fi

	return 1
}

is_valid_regulatory_region()
{
	local region_name=$1
	local region_list=$(call_qcsapi -u get_list_regulatory_regions)
	local reg

	for reg in $(echo "$region_list" | sed 's/,/ /g'); do
		if [ "$region_name" = "$reg" ]; then
			return 0
		fi
	done
	return 1
}

qhop_tmp_file=/tmp/qhop

feat_cred_file=$base_default_conf_file/custom_cred
feat_pkey_file=$base_default_conf_file/custom_pkey
feat_cred_file_mnt=$base_persistent_files/custom_cred
feat_pkey_file_mnt=$base_persistent_files/custom_pkey
feat_cred_file_tmp=/tmp/custom_cred
feat_pkey_file_tmp=/tmp/custom_pkey
