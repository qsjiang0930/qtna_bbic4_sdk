#############################################################
#
# traceroute
#
#############################################################


TRACEROUTE_VERSION:=2.1.0
TRACEROUTE_SOURCE:=traceroute-$(TRACEROUTE_VERSION).tar.gz
TRACEROUTE_BUILD_DIR:=$(BUILD_DIR)/traceroute-$(TRACEROUTE_VERSION)

$(TRACEROUTE_BUILD_DIR)/.unpacked: $(DL_DIR)/$(TRACEROUTE_SOURCE)
	$(ZCAT) $(DL_DIR)/$(TRACEROUTE_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(TRACEROUTE_BUILD_DIR) package/traceroute/ traceroute\*.patch
	touch $(TRACEROUTE_BUILD_DIR)/.unpacked

$(TRACEROUTE_BUILD_DIR)/traceroute/traceroute: $(TRACEROUTE_BUILD_DIR)/.unpacked
	$(MAKE) -C $(TRACEROUTE_BUILD_DIR) CC=$(TARGET_CC) CFLAGS="$(TARGET_CFLAGS) -DIPPROTO_DCCP=33 -DSOCK_DCCP=6" \
	LDFLAGS="$(TARGET_LDFLAGS)" BUILD_DIR="$(BUILD_DIR)" TOOLCHAIN_DIR="$(TOOLCHAIN_EXTERNAL_PATH)/$(TOOLCHAIN_EXTERNAL_PREFIX)"

traceroute: $(TRACEROUTE_BUILD_DIR)/traceroute/traceroute
	cp -fa $(TRACEROUTE_BUILD_DIR)/traceroute/traceroute $(TARGET_DIR)/usr/bin

traceroute-clean:
	-$(MAKE) -C $(TRACEROUTE_BUILD_DIR) clean

traceroute-dirclean:
	rm -rf $(TRACEROUTE_BUILD_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_TRACEROUTE)),y)
TARGETS+=traceroute
endif

