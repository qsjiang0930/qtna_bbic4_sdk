all: libqtn_hapd.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libqtn_hapd.a

install:
	@echo Nothing to be made.

include ../lib.rules

ifdef CONFIG_QTNA_WIFI
LIB_OBJS= \
	qtn_hapd_bss.o \
	qtn_hapd_pp.o \
	qtn_hapd_scs.o
else
LIB_OBJS=
endif

libqtn_hapd.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
