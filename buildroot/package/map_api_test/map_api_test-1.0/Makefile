ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS= -Wall -Wshadow -Werror
endif


TARGET_CFLAGS += -I../../../../drivers/include/shared
MAP_API_TEST_APP = map_api_test

$(MAP_API_TEST_APP): $(MAP_API_TEST_APP).c map_scan_test.c map_erw_test.c map_util_test.h map_scan_test.h
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) $^ -o $@

install: $(MAP_API_TEST_APP)
	install -D -m 755 $(MAP_API_TEST_APP) $(TARGET_DIR)/usr/sbin/

clean:
	rm -rf $(MAP_API_TEST_APP) *.o
