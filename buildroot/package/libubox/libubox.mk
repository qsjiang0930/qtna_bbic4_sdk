#############################################################
#
# libubox
#
#############################################################

LIBUBOX_SITE:=https://git.openwrt.org/project/libubox.git
LIBUBOX_VER:=3c1b33b
LIBUBOX_DIR:=$(BUILD_DIR)/libubox-$(LIBUBOX_VER)
LIBUBOX_SOURCE:=libubox-$(LIBUBOX_VER).tar.gz

export PKG_CONFIG_SYSROOT_DIR=$(STAGING_DIR)
export PKG_CONFIG_LIBDIR=$(STAGING_DIR)/lib/pkgconfig/

$(DL_DIR)/$(LIBUBOX_SOURCE):
	rm -rf $(DL_DIR)/libubox-tmp.git
	git clone $(LIBUBOX_SITE) $(DL_DIR)/libubox-tmp.git
	cd $(DL_DIR)/libubox-tmp.git; git archive --format=tar.gz --prefix=libubox-$(LIBUBOX_VER)/ --output=$(DL_DIR)/$(LIBUBOX_SOURCE) $(LIBUBOX_VER)
	rm -rf $(DL_DIR)/libubox-tmp.git

libubox-source: $(DL_DIR)/$(LIBUBOX_SOURCE)

$(LIBUBOX_DIR)/.unpacked: $(DL_DIR)/$(LIBUBOX_SOURCE)
	$(ZCAT) $(DL_DIR)/$(LIBUBOX_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(LIBUBOX_DIR) package/libubox/ "*.patch"
	touch $(LIBUBOX_DIR)/.unpacked

$(LIBUBOX_DIR)/.configured: $(LIBUBOX_DIR)/.unpacked
	(cd $(LIBUBOX_DIR); \
		CFLAGS="$(TARGET_CFLAGS) " \
		cmake \
			-DBUILD_LUA=OFF \
			-DBUILD_EXAMPLES=OFF \
			-DCMAKE_C_COMPILER=$(TARGET_CC) \
			-DCMAKE_INSTALL_PREFIX=/usr \
			-DCMAKE_PREFIX_PATH=$(STAGING_DIR) \
	);
	touch $(LIBUBOX_DIR)/.configured

$(LIBUBOX_DIR)/.compiled: $(LIBUBOX_DIR)/.configured
	$(MAKE) -C $(LIBUBOX_DIR)
	touch $(LIBUBOX_DIR)/.compiled

$(LIBUBOX_DIR)/.installed: $(LIBUBOX_DIR)/.compiled
	$(MAKE) -C $(LIBUBOX_DIR) DESTDIR=$(STAGING_DIR) install
	touch $(LIBUBOX_DIR)/.installed

$(TARGET_DIR)/usr/lib/libubox.so: $(LIBUBOX_DIR)/.installed
	cp -dpf $(STAGING_DIR)/usr/lib/libubox.so* $(TARGET_DIR)/usr/lib/
	-$(STRIP) --strip-unneeded $@

$(TARGET_DIR)/usr/lib/libblobmsg_json.so: $(LIBUBOX_DIR)/.installed
	cp -dpf $(STAGING_DIR)/usr/lib/libblobmsg_json.so* $(TARGET_DIR)/usr/lib/
	-$(STRIP) --strip-unneeded $@

libubox: uclibc $(TARGET_DIR)/usr/lib/libubox.so $(TARGET_DIR)/usr/lib/libblobmsg_json.so

libubox-clean:
	-$(MAKE) -C $(LIBUBOX_DIR) clean
	rm -f $(TARGET_DIR)/usr/lib/libubox.so*
	rm -f $(TARGET_DIR)/usr/lib/libblobmsg_json.so*

libubox-dirclean:
	rm -rf $(LIBUBOX_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_LIBUBOX)),y)
TARGETS+=libubox
endif
