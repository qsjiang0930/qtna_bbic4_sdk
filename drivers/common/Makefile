#
# Quantenna Communications, Inc. Driver makefile
#

EXTRA_CFLAGS += -Wall -Werror \
		-mlong-calls \
		-I../drivers \
		-I../include \
		-I../drivers/include/shared \
		-I../drivers/include/kernel \
		-DQTN_DEBUG

ifneq ($(KERNELRELEASE),)
obj-m += hw_rev.o
else

KERNELDIR	?= ../../linux-2.6.20.1
INSTALL		= INSTALL_MOD_PATH=../linux/modules
CROSS		= ARCH=arm CROSS_COMPILE=../buildroot/build_arm/staging_dir/bin/arm-linux-
PWD		:= $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) $(CROSS) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) $(CROSS) $(INSTALL) M=$(PWD) modules_install

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
