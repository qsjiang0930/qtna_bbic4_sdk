#############################################################
#
# libnl3
#
#############################################################

LIBNL3_VER:=3.2.27
LIBNL3_SOURCE:=libnl-$(LIBNL3_VER).tar.gz
LIBNL3_CAT:=$(ZCAT)
LIBNL3_DIR:=$(BUILD_DIR)/libnl-$(LIBNL3_VER)
LIBNL3_SITE:=http://sources.buildroot.net/
LIBNL3_LIBRARY:=libnl3
LIBNL3_TARGET_LIBRARY:=lib/libnl3
LIBNL3_LICENSE_FILES = COPYING
LIBNL3_INSTALL_STAGING = YES


LIBNL3_TARGET = $(TARGET_DIR)/$(LIBNL3_TARGET_LIBRARY)

$(eval $(autotools-package))

$(DL_DIR)/$(LIBNL3_SOURCE):
	$(WGET) -P $(DL_DIR) $(LIBNL3_SITE)/$(LIBNL3_SOURCE)

$(LIBNL3_DIR)/.unpacked: $(DL_DIR)/$(LIBNL3_SOURCE)
	$(ZCAT) $(DL_DIR)/$(LIBNL3_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(LIBNL3_DIR) package/libnl3/ libnl-$(LIBNL3_VER)-*.patch
	touch $(LIBNL3_DIR)/.unpacked

$(LIBNL3_DIR)/.configured: $(LIBNL3_DIR)/.unpacked
	(cd $(LIBNL3_DIR); \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS=-Os \
		LDFLAGS=-Wl,-rpath-link=$(STAGING_DIR)/lib \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--prefix=/usr \
		--exec-prefix=/usr \
		--bindir=/usr/bin \
		--sbindir=/usr/sbin \
		--libdir=/lib \
		--libexecdir=/usr/lib \
		--sysconfdir=/etc \
		--datadir=/usr/share \
		--localstatedir=/var \
		--includedir=/include \
		--mandir=/usr/man \
		--infodir=/usr/info \
		--disable-tftp \
		--disable-ftp \
		--disable-dict \
		--disable-file \
		--disable-imap \
		--disable-rtsp \
		--disable-pop3 \
		--disable-smtp \
		--disable-gopher \
		--disable-telnet \
		--disable-cli \
		$(LIBNL3_CONF_OPT) \
	);
	touch $(LIBNL3_DIR)/.configured;

$(LIBNL3_DIR)/$(LIBNL3_LIBRARY): $(LIBNL3_DIR)/.configured
	$(MAKE) CC=$(TARGET_CC) -C $(LIBNL3_DIR)

$(LIBNL3_TARGET): $(LIBNL3_DIR)/$(LIBNL3_LIBRARY)
	$(MAKE) DESTDIR=$(STAGING_DIR) -C $(LIBNL3_DIR) install
	cp -dpf $(LIBNL3_DIR)/lib/.libs/libnl-3.so* $(TARGET_DIR)/lib/
	cp -dpf $(LIBNL3_DIR)/lib/.libs/libnl-genl-3.so* $(TARGET_DIR)/lib/

libnl3: $(LIBNL3_TARGET)

libnl3-source: $(DL_DIR)/$(LIBNL3_SOURCE)

libnl3-clean:
	-rm $(TARGET_DIR)/lib/libnl-3.so*
	-rm $(TARGET_DIR)/lib/libnl-genl-3.so*
	-$(MAKE) -C $(LIBNL3_DIR) clean

libnl3-dirclean:
	-rm -rf $(LIBNL3_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################

ifeq ($(strip $(BR2_PACKAGE_LIBNL3)),y)
TARGETS+=libnl3
endif
