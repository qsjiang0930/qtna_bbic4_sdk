#(C)2016 Quantenna Communications Inc.

PKTLOGGER_D_BUILD_DIR ?= .

LIB_NAME = pkl
LIB_STATIC = lib$(LIB_NAME).a
LIB_LDNAME = lib$(LIB_NAME).so
LIB_SONAME = $(LIB_LDNAME).0.1

PKTLOGGERD       = pktlogger_d
PKTLOGGERD_SRC   = pktlogger_d.c
PKTLOGGERD_OBJS  = $(PKTLOGGERD).o

PKTLOGGERD_P     = $(PKTLOGGERD)_p

LIB_SRCS         = pkl.c
LIB_OBJS         = $(LIB_SRCS:.c=.o)

PKTLOGGER_NL_INC = ../../../../common/pktlogger
PKTLOGGER_NL_H   = $(PKTLOGGER_NL_INC)/pktlogger_nl_common.h
QL2T_INC         = ../../q_utils/q_utils-1.0.1/ql2t/lib
QL2T_LIB         = libql2t.so

CFLAGS += -Wall -Werror

.PHONY: all install install_prereq

ifneq ("$(wildcard $(PKTLOGGERD_SRC))","")
INSTALL_PREREQ=install_prereq
endif

all: $(PKTLOGGERD) $(LIB_SONAME) $(LIB_STATIC)

install_prereq: $(PKTLOGGERD) $(LIB_SONAME)

pktlogger_d.o: $(PKTLOGGERD_SRC) pktlogger_common.h $(PKTLOGGER_NL_H)
	$(CC) $(CFLAGS) -I$(PKTLOGGER_NL_INC) -I$(QL2T_INC) -c $(PKTLOGGERD_SRC)

$(PKTLOGGERD): $(PKTLOGGERD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PKTLOGGERD) $(PKTLOGGERD_OBJS) -L$(QL2T_INC) -l:$(QL2T_LIB)
	ln -fs $(PKTLOGGERD) $(PKTLOGGERD_P)

install: $(INSTALL_PREREQ)
	install -D $(PKTLOGGER_D_BUILD_DIR)/$(PKTLOGGERD) $(TARGET_DIR)/usr/sbin/$(PKTLOGGERD)
	cp -df $(PKTLOGGER_D_BUILD_DIR)/$(PKTLOGGERD_P) $(TARGET_DIR)/usr/sbin/$(PKTLOGGERD_P)
	install -D $(PKTLOGGER_D_BUILD_DIR)/$(LIB_SONAME) $(TARGET_DIR)/lib/$(LIB_SONAME)
	cp -df $(PKTLOGGER_D_BUILD_DIR)/$(LIB_LDNAME) $(TARGET_DIR)/lib/$(LIB_LDNAME)

pkl.o: pkl.c
	$(CC) $(CFLAGS) -I. -fPIC -O -g -Wall -Werror -Wno-unused-variable -Wno-unused-parameter -c $^

$(LIB_SONAME): $(LIB_OBJS)
	$(CC) -shared -s -o $@ -Wl,-soname,$(LIB_SONAME) -lc $^
	ln -fs $(LIB_SONAME) $(LIB_LDNAME)
	$(MAKE) -C test

$(LIB_STATIC): $(LIB_OBJS)
	$(AR) rcs $@ $^

.PHONY: clean
clean:
	@if [ -f $(PKTLOGGERD_SRC) ] ; then \
		rm -rf $(PKTLOGGERD) $(PKTLOGGERD_P) *.o *.so *.so.* *.a; \
		$(MAKE) -C test $@; \
	fi
