#
# Copyright (c) 2015-2016 Quantenna Communications, Inc.
# All rights reserved.
#

# need to be kept in sync with other config defines from qdrv, wlan, etc.
ccflags-y += -DQTN_BG_SCAN -DQBMPS_ENABLE
ccflags-y += -DCONFIG_QTN_80211K_SUPPORT

ccflags-y += -Wall -Werror -Wno-unknown-pragmas
ccflags-y += -I$(src)/../../include
ccflags-y += -I$(src)/../../common
ccflags-y += -I$(src)/../../drivers
ccflags-y += -I$(src)/../../drivers/include/shared
ccflags-y += -I$(src)/../../drivers/include/kernel

obj-m += qlink-ep.o
qlink-ep-objs := init.o command.o events.o wlan_ops.o netdev_ops.o vlan_ops.o \
	ie.o utils.o shm_ipc.o reg_utils.o crypto.o
