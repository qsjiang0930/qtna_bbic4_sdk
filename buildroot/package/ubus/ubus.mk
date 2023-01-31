#############################################################
#
# ubus
#
#############################################################

UBUS_SITE:=https://git.openwrt.org/project/ubus.git
UBUS_VER:=5bae22e
UBUS_DIR:=$(BUILD_DIR)/ubus-$(UBUS_VER)
UBUS_SOURCE:=ubus-$(UBUS_VER).tar.gz
UBUS_FILES=$(BASE_DIR)/package/ubus/files

$(DL_DIR)/$(UBUS_SOURCE):
	rm -rf $(DL_DIR)/ubus-tmp.git
	git clone $(UBUS_SITE) $(DL_DIR)/ubus-tmp.git
	cd $(DL_DIR)/ubus-tmp.git; git archive --format=tar.gz --prefix=ubus-$(UBUS_VER)/ --output=$(DL_DIR)/$(UBUS_SOURCE) $(UBUS_VER)
	rm -rf $(DL_DIR)/ubus-tmp.git

ubus-source: $(DL_DIR)/$(UBUS_SOURCE)

$(UBUS_DIR)/.unpacked: $(DL_DIR)/$(UBUS_SOURCE)
	$(ZCAT) $(DL_DIR)/$(UBUS_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(UBUS_DIR) package/ubus/ "*.patch"
	touch $(UBUS_DIR)/.unpacked

$(UBUS_DIR)/.configured: $(UBUS_DIR)/.unpacked
	(cd $(UBUS_DIR); \
		CFLAGS="$(TARGET_CFLAGS) " \
		cmake \
			-DBUILD_LUA=OFF \
			-DBUILD_EXAMPLES=OFF \
			-Dubox_include_dir=$(STAGING_DIR)/usr/include \
			-DCMAKE_C_COMPILER=$(TARGET_CC) \
			-DCMAKE_INSTALL_PREFIX=/usr \
			-DCMAKE_PREFIX_PATH=$(STAGING_DIR) \
	);
	touch $(UBUS_DIR)/.configured

$(UBUS_DIR)/.compiled: $(UBUS_DIR)/.configured
	$(MAKE) -C $(UBUS_DIR)
	touch $(UBUS_DIR)/.compiled

$(UBUS_DIR)/.installed: $(UBUS_DIR)/.compiled
	$(MAKE) -C $(UBUS_DIR) DESTDIR=$(STAGING_DIR) install
	touch $(UBUS_DIR)/.installed

$(TARGET_DIR)/usr/lib/libubus.so: $(UBUS_DIR)/.installed
	cp -dpf $(STAGING_DIR)/usr/lib/libubus.so* $(TARGET_DIR)/usr/lib/
	-$(STRIP) --strip-unneeded $@

$(TARGET_DIR)/usr/bin/ubus: $(UBUS_DIR)/.installed
	install -D $(STAGING_DIR)/usr/bin/ubus $@
	$(STRIP) -s $@

$(TARGET_DIR)/usr/sbin/ubusd: $(UBUS_DIR)/.installed
	install -D $(STAGING_DIR)/usr/sbin/ubusd $@
	$(STRIP) -s $@

ubus-files:
	install -m0755 -D $(UBUS_FILES)/S01ubus $(TARGET_DIR)/etc/init.d/

ubus: uclibc libubox $(TARGET_DIR)/usr/lib/libubus.so $(TARGET_DIR)/usr/bin/ubus $(TARGET_DIR)/usr/sbin/ubusd ubus-files

ubus-clean:
	-$(MAKE) -C $(UBUS_DIR) clean
	rm -f $(TARGET_DIR)/usr/bin/ubus
	rm -f $(TARGET_DIR)/usr/sbin/ubusd
	rm -f $(TARGET_DIR)/usr/lib/libubus.so*
	rm -f $(TARGET_DIR)/etc/init.d/S01ubus
	rm -rf $(TARGET_DIR)/etc/config

ubus-dirclean:
	rm -rf $(UBUS_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_UBUS)),y)
TARGETS+=ubus
endif
