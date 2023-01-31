#############################################################
#
# libinih
#
#############################################################
LIBINIH_VER:=42
LIBINIH_SOURCE:=libinih-r$(LIBINIH_VER).tar.gz
LIBINIH_CAT:=$(ZCAT)
LIBINIH_DIR:=$(BUILD_DIR)/inih-r$(LIBINIH_VER)/extra
LIBINIH_SITE:=https://github.com/benhoyt/inih/archive
LIBINIH_LIBRARY:=libinih
LIBINIH_TARGET_LIBRARY:=lib/libinih
LIBINIH_LICENSE_FILES = COPYING
LIBINIH_INSTALL_STAGING = YES


LIBINIH_TARGET = $(TARGET_DIR)/$(LIBINIH_TARGET_LIBRARY)

$(DL_DIR)/$(LIBINIH_SOURCE):
	$(WGET) -P $(DL_DIR) $(LIBINIH_SITE)/$(LIBINIH_SOURCE)

$(LIBINIH_DIR)/.unpacked: $(DL_DIR)/$(LIBINIH_SOURCE)
	$(ZCAT) $(DL_DIR)/$(LIBINIH_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $(LIBINIH_DIR)/.unpacked

$(LIBINIH_DIR)/.configured: $(LIBINIH_DIR)/.unpacked
	patch $(LIBINIH_DIR)/Makefile.static $(TOPDIR)/package/libinih/makefile-shared-lib.patch
	touch $(LIBINIH_DIR)/.configured

$(LIBINIH_DIR)/$(LIBINIH_LIBRARY): $(LIBINIH_DIR)/.configured
	$(MAKE) CC=$(TARGET_CC) -C $(LIBINIH_DIR) DESTDIR=$(STAGING_DIR) -f Makefile.static install

$(LIBINIH_TARGET): $(LIBINIH_DIR)/$(LIBINIH_LIBRARY)
	cp -dpf $(LIBINIH_DIR)/$(LIBINIH_LIBRARY).so $(TARGET_DIR)/lib/

libinih: $(LIBINIH_TARGET)

libinih-source: $(DL_DIR)/$(LIBINIH_SOURCE)

libinih-clean:
	-rm $(TARGET_DIR)/lib/$(LIBINIH_LIBRARY).so
	-$(MAKE) -C $(LIBINIH_DIR) -f Makefile.static clean

libinih-dirclean:
	-rm -rf $(LIBINIH_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_LIBINIH)),y)
TARGETS+=libinih
endif
