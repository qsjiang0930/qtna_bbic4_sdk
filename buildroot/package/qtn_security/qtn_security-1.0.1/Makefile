ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif

INSTALL_INCLUDE_STAGING = $(PREFIX)/../staging_dir/include/qtn
INSTALL_LIB_STAGING = $(PREFIX)/../staging_dir/lib

QSEC_LIB=libqsec.a

OBJS += qsec_config_utils.o
OBJS += qsec_file_utils.o

Q=@
E=echo
ifeq ($(V), 1)
Q=
E=true
endif

.PHONY: install install_inc install_lib clean

%.o: %.c
	$(Q)$(CC) -c -o $@ $(CFLAGS) $<
	@$(E) "  CC " $<

$(QSEC_LIB): $(OBJS)
	$(Q)ar rcs $@ $(OBJS)
	@$(E) "  AR " $@

install_inc: qsec_utils.h
	install -m 755 -d $(INSTALL_INCLUDE_STAGING)
	install -m 644 $^ $(INSTALL_INCLUDE_STAGING)

install_lib: $(QSEC_LIB)
	install -m 755 -d $(INSTALL_LIB_STAGING)
	install -m 644 $^ $(INSTALL_LIB_STAGING)

install: install_inc install_lib

clean:
	rm -f *~ *.o $(QSEC_LIB)
	rm -f *.d

-include $(OBJS:%.o=%.d)
