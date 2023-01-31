RANLIB = ranlib
VERSION ?= 1.0
ARCH ?= arc

QTMD = qtmd

INSTALL_DIR = $(TARGET_DIR)/usr/sbin/

CFLAGS += -I$(TOOLCHAIN_DIR)/include/ \
	  -I../../../../include/ \
	  -I../../../../drivers/include/shared/ \
	  -I$(STAGING_DIR)/include/libnl3/ \
	  -I../../../../common/ \
	  -I../../../../

CFLAGS += $(TARGET_CFLAGS)
CFLAGS += -Werror -Wall

CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AR=$(CROSS_COMPILE)ar

LDLIBS+= $(SYSLIBS)

LIBS = -lpthread -lm -lnl-3 -lnl-genl-3

LDFLAGS += -L./ \
	   -L$(TARGET_DIR)/usr/lib/ \
	   -L$(TARGET_DIR)/lib/ \
	   -L$(TARGET_DIR)/../staging_dir/lib/ \
	   -L$(STAGING_DIR)/lib/


QTM_SRCS = $(wildcard *.c)
QTM_OBJS = $(QTM_SRCS:.c=.o)

ifneq ($(strip $(QTM_SRCS)),)
ALL=all
endif

all: $(QTMD)

$(info QTM CFLAGS = $(CFLAGS))
$(info QTM LDFLAGS = $(LDFLAGS))

NETDEBUG_STRUCT_HEADERS := ../../../../include/qtn/qvsp_netdbg.h

qtm_netdbg.c: headers.txt

headers.txt: $(NETDEBUG_STRUCT_HEADERS)
	cat $(NETDEBUG_STRUCT_HEADERS) | \
		../../../../host/scripts/struct_get.sh |\
		grep -v '^[ 	]*$$' > headers.txt

$(QTMD): $(QTM_OBJS)
	$(CC) $(LDFLAGS) -g -O2 -o $@ $(QTM_OBJS) $(LIBS) $(LDLIBS) -I include -L. -D__LINUX

install: $(ALL)
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(QTMD) $(INSTALL_DIR)

.c.o:
	$(CC) $(CFLAGS) -g -pipe -D__LINUX -fPIC -c $<

dwarf: qtm_netdbg.o
	$(CROSS_COMPILE)readelf --debug-dump=info qtm_netdbg.o > $(DWARF_FILE)
	cp headers.txt $(HEADERS_FILE) || :

clean:
	-rm -rf *.o *.so *.so.* headers.txt

distclean: clean
	@-rm -rf $(QTMD)
	@-rm $(INSTALL_DIR)/$(QTMD)
