#############################################################
#
# Radio Peer Entity
#
#############################################################
QRPE_VERSION:=9.0.0
QRPE_BUILD_DIR=$(BUILD_DIR)/qrpe-$(QRPE_VERSION)/src
QRPE_SOURCE=qrpe-$(QRPE_VERSION).tar.gz
QRPE_PATCH_DIR=package/qrpe/patches/$(QRPE_VERSION)
ifneq ("$(wildcard $(QRPE_PATCH_DIR)/*.patch)","")
QRPE_PATCH_MAX=$(shell ls $(QRPE_PATCH_DIR) |tail -n1 |cut -c1-4)
QRPE_PATCH_MAXNO_VER=$(shell echo "\#define QRPE_PATCH_MAXNO \"$(QRPE_PATCH_MAX)\"")
else
QRPE_PATCH_MAXNO_VER=
endif

export TARGET_DIR

.PHONY: FORCE

$(QRPE_BUILD_DIR)/.unpacked:
	$(ZCAT) $(DL_DIR)/$(QRPE_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	cp $(QRPE_BUILD_DIR)/qrpe.topaz.config  $(QRPE_BUILD_DIR)/qrpe.config
	if test -d $(QRPE_PATCH_DIR); then toolchain/patch-kernel.sh $(BUILD_DIR)/qrpe-$(QRPE_VERSION) $(QRPE_PATCH_DIR) \*.patch; fi;
	echo "$(QRPE_PATCH_MAXNO_VER)" >> $(QRPE_BUILD_DIR)/version.h
	touch $(QRPE_BUILD_DIR)/.unpacked

qrpe: qcsapi $(QRPE_BUILD_DIR)/.unpacked
	$(MAKE) -C $(QRPE_BUILD_DIR) CC=$(TARGET_CC) SDK_DIR=$(TOPDIR)/.. STAGING_DIR=$(STAGING_DIR) all install
	install -D -m 755 package/qrpe/start_qrpe $(TARGET_DIR)/scripts/start_qrpe

qrpe-clean:
	-$(MAKE) -C $(QRPE_BUILD_DIR) clean

qrpe-dirclean: qrpe-clean
	rm -f $(TARGET_DIR)/usr/sbin/qrpe

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_QRPE)),y)
TARGETS+=qrpe
endif
