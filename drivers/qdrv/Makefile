#
# Quantenna Communications Inc. Driver Makefile
#

EXTRA_CFLAGS += -Wall -Werror -Wno-unknown-pragmas -DQDRV \
		-I../drivers -I../include -I../common \
		-I../drivers/include/shared -I../drivers/include/kernel
EXTRA_CFLAGS += -mlong-calls
EXTRA_CFLAGS += -DQTN_ENABLE_TRACE_BUFFER=0 -DQSCS_ENABLED -DQTN_BG_SCAN -DQBMPS_ENABLE
EXTRA_CFLAGS += -DCONFIG_QTN_80211K_SUPPORT -DCONFIG_NAC_MONITOR

ifeq ($(CONFIG_QVSP), y)
EXTRA_CFLAGS += -DCONFIG_QVSP
endif
EXTRA_CFLAGS += -DQTN_DEBUG

ifeq ($(board_config), qtm710_rgmii_config)
EXTRA_CFLAGS += -DQTM710_RGMII_CONFIG
endif

ifeq ($(board_config),topaz_msft_config)
	EXTRA_CFLAGS += -DERICSSON_CONFIG
else
	ifeq ($(board_config),topaz_msmr_config)
		EXTRA_CFLAGS += -DERICSSON_CONFIG
	endif
endif

ifeq ($(CONFIG_TOPAZ_FILTER_HBM_LEVEL2),y)
	EXTRA_CFLAGS += -DTOPAZ_FILTER_HBM_LEVEL2
endif

EXTRA_CFLAGS += -g      # needed for pktlogger

SOURCE_MODULES := qdrv_module.o qdrv_control.o qdrv_soc.o \
			qdrv_hal.o qdrv_muc.o qdrv_mac.o qdrv_mac_reserve.o qdrv_comm.o \
			qdrv_wlan.o qdrv_tx.o qdrv_rx.o qdrv_scan.o \
			qdrv_hostlink.o qdrv_vap.o \
			qdrv_dsp.o qdrv_txbf.o qdrv_muc_stats.o \
			qdrv_radar.o qdrv_math.o qdrv_bridge.o \
			qdrv_uc_print.o qdrv_sch.o qdrv_sch_pm.o \
			qdrv_pktlogger.o qdrv_auc.o qdrv_pcap.o	\
			qdrv_vlan.o qdrv_show.o \
			qdrv_mu.o qdrv_fw.o qdrv_spdia.o

ifneq ($(KERNELRELEASE),)

obj-m		+=	qdrv.o
qdrv-objs	+=	$(SOURCE_MODULES)

else # $(KERNELRELEASE)

include ../Makefile_defines

DWARF_FILE	?= ./qdrv_dwarf.txt

default:
	$(MAKE) -C $(KERNELDIR) \
		ARCH=$(ARCHITECTURE) \
		CROSS_COMPILE=$(TOOLS_PREFIX) \
		M=$(PWD) \
		modules

install:
	$(MAKE) -C $(KERNELDIR) \
		ARCH=$(ARCHITECTURE) \
		CROSS_COMPILE=$(TOOLS_PREFIX) \
		M=$(PWD) \
		INSTALL_MOD_PATH=$(INSTALL_PATH) \
		modules_install

dwarf:
	$(TOOLS_PREFIX)readelf --debug-dump=info qdrv.o > $(DWARF_FILE)
	cp headers.txt $(HEADERS_FILE) || :

clean:
	$(MAKE) -C $(KERNELDIR) $(CROSS) M=$(PWD) clean

endif # $(KERNELRELEASE)

clean-files+=$(CLEAN_FILES)
