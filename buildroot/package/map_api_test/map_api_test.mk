#############################################################
#
# map_api_test
#
#############################################################
MAP_API_TEST_VERSION:=1.0
MAP_API_TEST_DIR:=$(TOPDIR)/package/map_api_test/map_api_test-$(MAP_API_TEST_VERSION)
EXTRA_WARNINGS= -Wall -Wshadow -Werror


map_api_test:
	$(MAKE) -C $(MAP_API_TEST_DIR) PREFIX="$(TARGET_DIR)" \
                LDFLAGS="-L$(TARGET_DIR)/lib" \
                CC=$(TARGET_CC) CFLAGS="$(TARGET_CFLAGS) $(EXTRA_WARNINGS)" \
                install

map_api_test-clean:
	$(MAKE) -C $(MAP_API_TEST_DIR) clean

map_api_test-distclean: map_api_test-clean
#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_MAP_API_TEST)),y)
TARGETS+=map_api_test
endif

