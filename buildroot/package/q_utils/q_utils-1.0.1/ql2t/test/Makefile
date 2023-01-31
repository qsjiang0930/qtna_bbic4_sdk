PROG:=ql2t_test
INSTALL_DIR:=$(PREFIX)/sbin/

OBJS:=ql2t_test.o

.PHONY: all
all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -lql2t -o $@ $<

%.o: %.c ../lib/ql2t.h
	$(CC) -c $(CFLAGS) -I../lib -o $@ $<

.PHONY: install
install: $(PROG)
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(PROG) $(INSTALL_DIR)

.PHONY: clean
clean:
	rm -f *.o $(PROG)

.PHONY: distclean
distclean: clean
