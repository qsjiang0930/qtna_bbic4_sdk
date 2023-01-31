#
# Quantenna Communications Inc. Driver Makefile
#
#

EXTRA_CFLAGS	+= -Wall -Werror -I../include
EXTRA_CFLAGS    += -mlong-calls

ifneq ($(KERNELRELEASE),)
qtn-debug-objs += qtn_debug.o
obj-m   += qtn_debug.o
else

INSTALL	= INSTALL_MOD_PATH=../linux/modules
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) $(CROSS) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) $(CROSS) $(INSTALL) M=$(PWD) modules_install

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

