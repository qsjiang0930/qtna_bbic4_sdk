ifndef LIBQCSAPI_CLIENT_DIR
LIBQCSAPI_CLIENT_DIR = ../qcsapi-client/libqcsapi_client_src
endif

# warnings: -Wall -Werror -Wextra -Wshadow -Wno-unused-parameter
CFLAGS += -Wall -Werror -std=gnu99

# include dirs
CFLAGS += -I$(LIBQCSAPI_CLIENT_DIR)

# Generate dependency information
CFLAGS += -MD -MP -MF .dep/$(@F).d

LDFLAGS += -L$(LIBQCSAPI_CLIENT_DIR)

LIBS = -lqcsapi_client -lpthread

PROG = qtn_sigma_ca

OBJ_LIST = \
	src/qtn_ca_main.o \
	src/qtn_ca_config.o \
	src/qtn_common.o \
	src/qtn_cmd_tokens.o \
	src/qtn_cmd_parser.o \
	src/qtn_cmd_modules.o \
	src/qtn_defconf.o \
	src/qtn_ap_handler.o \
	src/qtn_hs2_handler.o \
	src/qtn_sta_handler.o


all: $(PROG)

$(PROG): $(OBJ_LIST)
	$(CC) $^ -o $@ $(LDFLAGS) $(LIBS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(PROG) $(OBJ_LIST)

all_srctars:
	tar cvf quantenna-sigma_ca_src.tar Makefile src config

.PHONY: clean all

# Include the dependency files, should be the last of the makefile
-include $(shell mkdir .dep 2>/dev/null) $(wildcard .dep/*)
