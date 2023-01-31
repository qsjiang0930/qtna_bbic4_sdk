LIB:=libql2t.so
LIB_STATIC:=libql2t.a
INSTALL_DIR:=$(PREFIX)/lib/

OBJS:=ql2t.o

.PHONY: all
all: $(LIB) $(LIB_STATIC)

$(LIB): $(OBJS)
	$(CC) -shared -o $@ $<

$(LIB_STATIC): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c ql2t.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

.PHONY: install
install: $(LIB)
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(LIB) $(INSTALL_DIR)

.PHONY: clean
clean:
	rm -f *.o $(LIB) $(LIB_STATIC)

.PHONY: distclean
distclean: clean
