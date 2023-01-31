RANLIB = ranlib
VERSION ?= 1.0
ARCH ?= arc

PROGS = qweb
QWEBAPI_NAME = libqwebapi
QWEBAPI_LIBS = $(QWEBAPI_NAME).so

GENERATE_DIR = $(shell pwd)/generated

INSTALL_DIR = $(TARGET_DIR)/usr/sbin/
INSTALL_INC = $(TARGET_DIR)/../../include
INSTALL_INCLUDE_STAGING = $(TARGET_DIR)/../staging_dir/include/qtn
INSTALL_LIB_STAGING = $(TARGET_DIR)/../staging_dir/

CFLAGS += -I$(TOOLCHAIN_DIR)/include/ \
	  -I$(BUILD_DIR)/staging_dir/include/ \
	  -I$(BUILD_DIR)/../../include/ \
	  -I$(BUILD_DIR)/../../drivers/include/shared/ \
	  -I$(BUILD_DIR)/../../ \
	  -I$(BUILD_DIR)/staging_dir/include/qtn/ \
	  -I../../qcsapi/qcsapi-1.0.1/

CFLAGS += $(TARGET_CFLAGS)
CFLAGS += -Werror -Wall
#CFLAGS += -DQTN_DEBUG
#CFLAGS += -DHAVE_DEBUG_FILE

ifneq ($(findstring topaz_dbdc,$(board_config)),)
CFLAGS += -DTOPAZ_DBDC
endif

ifneq ($(findstring topaz_qfdr_config,$(board_config)),)
CFLAGS += -DTOPAZ_QFDR -DTOPAZ_DBDC
endif

CC=$(TARGET_CROSS)gcc
LD=$(TARGET_CROSS)ld
AR=$(TARGET_CROSS)ar

LDLIBS+= $(SYSLIBS)
LDLIBS+= -ljson

LIBS = -lpthread -lm -lqcsapi -lz

LDFLAGS += -L./ \
	   -L$(TARGET_DIR)/usr/lib/ \
	   -L$(TARGET_DIR)/lib/ \
	   -L$(TARGET_DIR)/../staging_dir/lib/ \
	   -L$(BUILD_DIR)/staging_dir/lib/

QWEB_OBJS = qweb.o
LIB_OBJS := qwebapi.o qwebapi_tr181.o qwebapi_tr181_adaptor.o qwebapi_debug.o qwebapi_util.o

QWEBCFG = qwebcfg
QWEBCFG_SRCS = qwebcfg.c
QWEBCFG_OBJS = $(QWEBCFG_SRCS:.c=.o)

all: $(PROGS) $(QWEBAPI_NAME) $(QWEBCFG)

$(PROGS): $(QWEB_OBJS) $(QWEBAPI_NAME)
	$(CC) $(LDFLAGS) -g -O2 -o $@ $(QWEB_OBJS) -lqwebapi $(LIBS) $(LDLIBS) -I include -L. -D__LINUX

$(QWEBCFG): $(QWEBCFG_OBJS) $(QWEBAPI_NAME)
	$(CC) $(LDFLAGS) -g -O2 -o $@ $(QWEBCFG_OBJS) -lqwebapi $(LIBS) $(LDLIBS) -I include -L. -D__LINUX

$(QWEBAPI_NAME):.prepare $(LIB_OBJS) install_inc
	$(CC) $(LDFLAGS) -g -O2 -pipe -fPIC -shared -o $@.so -Wl,-soname,$(QWEBAPI_LIBS) $(LIB_OBJS) $(LDLIBS) -lc -I include -D__LINUX

.prepare:
	-mkdir -p $(GENERATE_DIR)
	touch .prepare

install: $(PROGS) $(QWEBCFG)
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(PROGS) $(INSTALL_DIR)
	install -m 755 $(QWEBCFG) $(INSTALL_DIR)
	install -m 755 $(QWEBAPI_LIBS) $(TARGET_DIR)/usr/lib/
	install -m 755 $(QWEBAPI_LIBS) $(INSTALL_LIB_STAGING)/usr/lib/
	mv $(QWEBAPI_LIBS) $(GENERATE_DIR)/
	mv $(PROGS) $(GENERATE_DIR)/
	mv *.o $(GENERATE_DIR)/

install_inc: qwebapi.h
	install -m 755 -d $(INSTALL_INC)
	install -m 644 $^ $(INSTALL_INC)
	install -m 755 -d $(INSTALL_INCLUDE_STAGING)
	install -m 755 $^ $(INSTALL_INCLUDE_STAGING)

.c.o:
	$(CC) $(CFLAGS) -g -pipe -D__LINUX -fPIC -c $<

clean:
	-rm -rf *.o *.so *.so.*

distclean: clean
	@-rm -rf $(PROGS)
	@-rm .prepare
	@-rm $(GENERATE_DIR) -rf
	@-rm $(INSTALL_DIR)/$(PROGS)
	@-rm $(TARGET_DIR)/usr/lib/$(QWEBAPI_LIBS)
