##
## Please check the configurion parameters below
##

## Installation directory. By default, go in /usr/local.
## Distributions should probably use /, but they probably know better...
ifndef PREFIX
	PREFIX = /usr/local
endif

## by a few percent but make debug worse...
# BUILD_STRIPPING = y

# ***************************************************************************
# ***** Most users should not need to change anything beyond this point *****
# ***************************************************************************

# Targets to build
PROGS= qserver qserver_cli

# Install directories
INSTALL_DIR= $(PREFIX)/sbin/

# Various commands
RM = rm -f
RM_CMD = $(RM) *.BAK *.bak *.d *.o *.so ,* *~ *.a *.orig *.rej *.out *.gch
LDCONFIG = ldconfig

# Stripping or not ?
ifdef BUILD_STRIPPING
	STRIPFLAGS= -Wl,-s
else
	STRIPFLAGS=
endif

# Other flags
OBJS = eloop.o l2_packet.o driver_quantenna.o qhop.o link_switch_sm.o qserver_frame.o	\
       qserver_ctrl_iface.o qserver.o ./crypto/sha1.o ./crypto/sha1-internal.o	\
       ./crypto/sha1-pbkdf2.o ./crypto/sha256-internal.o ./crypto/md5-internal.o

HEADERS = commons.h eloop.h l2_packet.h qhop.h link_switch_sm.h qserver_frame.h	\
	  qserver_ctrl_iface.h qdata.h driver.h wireless.h ./crypto/sha1.h	\
	  ./crypto/sha1_i.h ./crypto/sha256_i.h	./crypto/md5_i.h

INCLUDES = -I.	\
	   -I./crypto/	\
	   -I../../../../drivers/include/shared/	\
	   -I../../qcsapi/qcsapi-1.0.1/			\
	   -I../../../../include/			\
	   -I../../../../

LIBS = -L$(PREFIX)/lib -lqcsapi -lpthread -lz -ldl

CFLAGS += -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow \
	-Wpointer-arith -Wno-cast-qual -Winline -Werror

DEPFLAGS += -MMD
XCFLAGS += $(CFLAGS) $(DEPFLAGS) $(WARN) $(WELIB_FLAG)

# Standard compilation targets
all:: $(PROGS)

qserver: $(OBJS)
	$(CC) $(LDFLAGS) $(STRIPFLAGS) $(XCFLAGS) $(INCLUDES) $(LIBS) -o $@ $^ -MD -MF $@.d

qserver_cli: qserver_cli.o
	$(CC) $(LDFLAGS) $(STRIPFLAGS) $(XCFLAGS) $(INCLUDES) -o $@ $^ -MD -MF $@.d

%.o: Makefile

%.o: %.c $(HEADERS)
	$(CC) $(XCFLAGS) $(INCLUDES) -c -o $@ $< -MD -MF $@.d

# All the binaries.
install:: all
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(PROGS) $(INSTALL_DIR)

clean::
	$(RM_CMD)
	$(RM) $(PROGS)
	$(MAKE) -C ./crypto/ clean

uninstall::
	for f in $(PROGS); do \
		$(RM) $(INSTALL_DIR)/$$f; \
	done

# Include dependancies
-include *.d
