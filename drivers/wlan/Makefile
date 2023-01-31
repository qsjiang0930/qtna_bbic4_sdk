#
# Author: Mats Aretun
#

EXTRA_CFLAGS += -Wall -Werror  -I$(PWD) -I../include -DDEBUG -DDEMO_CONTROL
EXTRA_CFLAGS += -I../drivers/include/shared -I../drivers/include/kernel -I../drivers/
EXTRA_CFLAGS += -mlong-calls
EXTRA_CFLAGS += -DQDRV -DQSCS_ENABLED -DQTN_BG_SCAN -DQBMPS_ENABLE
EXTRA_CFLAGS += -DCONFIG_QTN_80211K_SUPPORT
EXTRA_CFLAGS += -DQTN_DYN_CCA=1
# Non associated clients monitoring support
EXTRA_CFLAGS += -DCONFIG_NAC_MONITOR

ifneq ($(KERNELRELEASE),)

wlan-objs	+=	if_media.o \
				ieee80211_beacon.o \
				ieee80211_beacon_desc.o \
				ieee80211_crypto.o \
				ieee80211_crypto_none.o \
				ieee80211_chan_select.o \
				ieee80211_proto.o \
				ieee80211_output.o \
				ieee80211_power.o \
				ieee80211_scan.o \
				ieee80211_wireless.o \
				ieee80211_linux.o \
				ieee80211_rate.o \
				ieee80211_input.o \
				ieee80211_node.o \
				ieee80211_tdls.o \
				ieee80211_tpc.o \
				ieee80211_mlme_statistics.o \
				ieee80211.o \
				ieee80211_repeater.o \
				ieee80211_mfr.o	\
				ieee80211_wnm.o

wlan_acl-objs		+=	ieee80211_acl.o
wlan_scan_sta-objs	+=	ieee80211_scan_sta.o
wlan_scan_ap-objs	+=	ieee80211_scan_ap.o
ifeq (qfdr,$(findstring qfdr,$(board_config)))
wlan_qfdr-objs		+=	ieee80211_qfdr.o
endif

ifeq ($(support_artsmng), 1)
wlan-objs	+=	artsioctl.o \
			artsmng.o
endif

wlan_ccmp-objs  += ieee80211_crypto_ccmp.o
wlan_tkip-objs  += ieee80211_crypto_tkip.o
wlan_xauth-objs := ieee80211_xauth.o

obj-m += wlan.o
obj-m += wlan_acl.o
obj-m += wlan_scan_ap.o
obj-m += wlan_scan_sta.o
obj-m += wlan_ccmp.o
obj-m += wlan_tkip.o
obj-m += wlan_xauth.o
ifeq (qfdr,$(findstring qfdr,$(board_config)))
obj-m += wlan_qfdr.o
endif

else

#KERNELDIR	?= /lib/modules/$(shell uname -r)/build
KERNELDIR	?= ../../linux-2.6.20.1
INSTALL		= INSTALL_MOD_PATH=../linux/modules
CROSS		= ARCH=arm CROSS_COMPILE=../buildroot/build_arm/staging_dir/bin/arm-linux-
PWD			:= $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) $(CROSS) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) $(CROSS) $(INSTALL) M=$(PWD) modules_install

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
