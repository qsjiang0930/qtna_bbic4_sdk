#
# Copyright (c) 2011-2012 Quantenna Communications, Inc.
#

EXTRA_CFLAGS += -Wall -Werror -mlong-calls \
		-I../drivers -I../include -I../drivers/include/shared -I../drivers/include/kernel

EXTRA_CFLAGS += -DCONFIG_QTN_80211K_SUPPORT

SOURCE_MODULES := qvsp.o qvsp_cfg.o qvsp_netdbg.o qvsp_nl.o

ifneq ($(KERNELRELEASE),)
obj-m += qvspmod.o
qvspmod-objs += $(SOURCE_MODULES)

else # $(KERNELRELEASE)

include ../Makefile_defines

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

endif # $(KERNELRELEASE)

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions \
		Module.symvers

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
