#
# Quantenna Communications Inc. Driver Makefile
#
# Author:
#
EXTRA_CFLAGS	+= -Wall -Werror -Wno-unknown-pragmas\
		   -I../include \
		   -I../common \
		   -I../drivers/include/shared \
		   -I../drivers/include/kernel

EXTRA_CFLAGS    += -I$(M)/pcie2/include -I$(M)/pcie2/target
EXTRA_CFLAGS    += -mlong-calls

PCIE_TQE_DIR = ../tqe

#EXTRA_CFLAGS    += -DDEBUG
ifneq ($(KERNELRELEASE),)
qdpc-pcie-objs   := topaz_vnet.o topaz_pcie_dma.o\
		$(PCIE_TQE_DIR)/topaz_pcie_tqe.o qdpc_pcie.o

obj-m           := qdpc-pcie.o
else

KERNELDIR	?= ../../../linux
INSTALL		= INSTALL_MOD_PATH=../linux/modules
CROSS		= ARCH=arc CROSS_COMPILE=/toolsbuild/scratch/opt/arc2/uclibc/bin/arc-linux-uclibc-
PWD		:= $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) $(CROSS) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) $(CROSS) $(INSTALL) M=$(PWD) modules_install

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers modules.order

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
