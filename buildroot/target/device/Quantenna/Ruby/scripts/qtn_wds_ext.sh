#! /bin/sh

base_scripts="/scripts"

. $base_scripts/start-helpers.sh

script=`basename $0`

show_help()
{
	echo "Usage:"
	echo "      $script <cmd> [peer=<mac address>] [channel=<channel>] [wds_key=<key>] [bw=<bw>]"
	echo "      Available <cmd> are: START-AP-RBS, START-STA-RBS,"
	echo "            MBS-CREATE-WDS-LINK, RBS-CREATE-WDS-LINK,"
	echo "            MBS-REMOVE-WDS-LINK, RBS-REMOVE-WDS-LINK, REMOVE-WDS-LINK,"
	echo "            MBS-UPDATE-WDS-KEY, RBS-UPDATE-WDS-KEY"
	echo "            and RBS-SET-CHANNEL"
	exit 1
}

get_verbose()
{
	verbose=`call_qcsapi -u get_extender_status wifi0 | grep verbose`
	verbose=`echo $verbose | awk '{print $2}'`
}

verify_wds_mode()
{
	repeater_mode=`call_qcsapi -u verify_repeater_mode`
	if [ $repeater_mode -eq 1 ]; then
		echo "Error: WDS mode is not supported in repeater mode"
		exit 1
	fi
	curr_wds_mode=`call_qcsapi -u get_extender_status wifi0 | grep role`
	curr_wds_mode=`echo $curr_wds_mode | awk '{print $2}'`
	if [ $curr_wds_mode'x' == $wds_mode'x' ] ; then
		return 0
	else
		echo "Error: WDS mode is invalid, current mode is $curr_wds_mode"
		exit 1
	fi
}

qsteer_set_backbone()
{
	qsteer=`get_wifi_config wifi0 qsteer`

	if [ $qsteer -eq 1 ]
	then
		bssid=`call_qcsapi -u get_BSSID wifi0`
		qcomm_cli set_backbone $bssid
	fi
}

start_ap_rbs()
{
	verify_wds_mode

	if [ $wds_key == "NULL" ]; then
		security_on=""
	else
		security_on="encrypt"
	fi

	echo "bw=$bw channel=$channel" > $qhop_tmp_file

	# For 'reload_in_mode', use of '-u' is forbidden since it may cause
	# new 'reload_in_mode' is triggered before the previous one finishes
	call_qcsapi reload_in_mode wifi0 ap

	call_qcsapi -u wait_scan_completes wifi0 30

	call_qcsapi -u wds_add_peer wifi0 $peer_mac $security_on
	if [ $security_on'X' != 'X' ]; then
		call_qcsapi -u wds_set_psk wifi0 $peer_mac $wds_key
	fi
	call_qcsapi -u wds_set_mode wifi0 $peer_mac rbs

	rm -f $qhop_tmp_file

	qsteer_set_backbone
}

start_sta_rbs()
{
	verify_wds_mode
	wifi_mode=`get_wifi_config wifi0 mode`
	if [ $wifi_mode"X" == "sta""X" ] ; then
		# Stop wifix devices to avoid receiving MBS beacons
		# in reload_in_mode procedure
		for dev in `ls -1 /sys/devices/virtual/net/ | grep -E 'wifi'` ; do
			ifconfig $dev down
		done

		call_qcsapi -u wds_remove_peer wifi0 $peer_mac
		call_qcsapi reload_in_mode wifi0 sta
	fi
}

create_wds_link()
{
	verify_wds_mode

	if [ $wds_key == "NULL" ]; then
		security_on=""
	else
		security_on="encrypt"
	fi
	call_qcsapi -u wds_add_peer wifi0 $peer_mac $security_on
	if [ $security_on'X' != 'X' ]; then
		call_qcsapi -u wds_set_psk wifi0 $peer_mac $wds_key
	fi
}

mbs_create_wds_link()
{
	create_wds_link
	call_qcsapi -u wds_set_mode wifi0 $peer_mac mbs
}

rbs_create_wds_link()
{
	call_qcsapi -u set_channel wifi0 $channel
	create_wds_link
	call_qcsapi -u wds_set_mode wifi0 $peer_mac rbs

	qsteer_set_backbone
}

rbs_remove_wds_link()
{
	verify_wds_mode
	wifi_mode=`get_wifi_config wifi0 mode`
	if [ $wifi_mode"X" == "sta""X" ] ; then
		call_qcsapi reload_in_mode wifi0 sta
	else
		call_qcsapi -u wds_remove_peer wifi0 $peer_mac
	fi
}

mbs_remove_wds_link()
{
	verify_wds_mode
	call_qcsapi -u wds_remove_peer wifi0 $peer_mac
}

get_verbose
if [ $verbose'X' == "2"'X' ]; then
	echo "cmd: $script $*" > /dev/console
fi

for temp in $*
do
	case $temp in
	peer=*)
		peer_mac=`echo $temp | cut -d '=' -f2`
	;;
	wds_key=*)
		wds_key=`echo $temp | cut -d '=' -f2`
	;;
	channel=*)
		channel=`echo $temp | cut -d '=' -f2`
	;;
	bw=*)
		bw=`echo $temp | cut -d '=' -f2`
	esac
done

if [ $1'X' == "START-AP-RBS"'X' ]; then
	if [ $peer_mac'X' == 'X' -o $channel'X' == 'X' -o \
			$wds_key'X' == 'X' ]; then
		show_help
	fi
	wds_mode=RBS
	start_ap_rbs
elif [ $1'X' == "START-STA-RBS"'X' ]; then
	wds_mode=RBS
	start_sta_rbs
elif [ $1'X' == "MBS-CREATE-WDS-LINK"'X' ]; then
	if [ $peer_mac'X' == 'X' -o $wds_key'X' == 'X' ]; then
		show_help
	fi
	wds_mode=MBS
	mbs_create_wds_link
elif [ $1'X' == "RBS-CREATE-WDS-LINK"'X' ]; then
	if [ $peer_mac'X' == 'X' -o $channel'X' == 'X' -o \
			$wds_key'X' == 'X' ]; then
		show_help
	fi

	wifi_mode=`get_wifi_config wifi0 mode`
	if [ $wifi_mode"X" == "sta""X" ] ; then
		if [ $verbose'X' == "2"'X' ]; then
			echo "$script : Event $1 ignored by RBS (STA mode)" > /dev/console
		fi
		exit
	fi

	wds_mode=RBS
	rbs_create_wds_link
elif [ $1'X' == "MBS-REMOVE-WDS-LINK"'X' ]; then
	if [ $peer_mac'X' == 'X' ]; then
		show_help
	fi
	wds_mode=MBS
	mbs_remove_wds_link
elif [ $1'X' == "RBS-REMOVE-WDS-LINK"'X' ]; then
	if [ $peer_mac'X' == 'X' ]; then
		show_help
	fi
	wds_mode=RBS
	rbs_remove_wds_link
elif [ $1'X' == "RBS-SET-CHANNEL"'X' ]; then
	if [ $channel'X' == 'X' ]; then
		show_chelp
	fi
	call_qcsapi -u set_channel wifi0 $channel
elif [ $1'X' == "REMOVE-WDS-LINK"'X' ]; then
	if [ $peer_mac'X' == 'X' ]; then
		show_help
	fi
	call_qcsapi -u wds_remove_peer wifi0 $peer_mac
elif [ "$1" == "MBS-UPDATE-WDS-KEY" -o "$1" == "RBS-UPDATE-WDS-KEY" ]; then
	if [ "$peer_mac" == "" ]; then
		show_help
	fi
	call_qcsapi -u wds_set_psk wifi0 $peer_mac $wds_key
else
	show_help
fi
