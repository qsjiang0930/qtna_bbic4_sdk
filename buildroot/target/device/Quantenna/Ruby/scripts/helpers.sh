#!/bin/sh
#
# Utility functions

bin=`basename $0`

base_scripts="/scripts"

# Get hardware revision string - bbic3, bbic4, bbic5, etc.
get_hw_rev()
{
	hw_rev=`cat /proc/hw_revision 2>/dev/null | sed 's/^\(bbic[0-9]*\).*/\1/'`

	if [ "$hw_rev" = "" ]; then
		hw_rev="unknown"
	fi

	echo $hw_rev
}

# Get hardware revision number - 3, 4, 5, etc.
get_hw_rev_id()
{
	hw_rev_id=0

	rev_id=`cat /proc/hw_revision 2>/dev/null | sed 's/^bbic\([0-9]*\).*/\1/'`
	let "hw_rev_id = $rev_id + 0" 2>/dev/null

	echo $hw_rev_id
}

# Get hardware platform - ruby, topaz, pearl, etc.
get_hw_plat()
{
	hw_rev=`get_hw_rev`
	case $hw_rev in
	bbic3)	echo "ruby"
		;;
	bbic4)	echo "topaz"
		;;
	bbic5)	echo "pearl"
		;;
	*)	echo "unknown"
		;;
	esac
}

check_mac()
{
	check=`echo "$1" | sed -e 's/\([0-9a-fA-F]\{2\}:\)\{5\}[0-9a-fA-F]\{2\}//'`
	if [ "$check" != "" ]
	then
		return 1
	fi

	return 0
}
