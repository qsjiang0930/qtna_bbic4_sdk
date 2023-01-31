#############################################################
#
# Quantenna private connection managment daemon
#
#############################################################

QM_DIR=$(TOPDIR)/package/qserver

.PHONY: qserver

QSERVER_VER:=1.0
QSERVER_SUBVER:=

QSERVER_BUILD_DIR=$(QM_DIR)/qserver-$(QSERVER_VER)

qserver:
	$(MAKE) -C $(QSERVER_BUILD_DIR) PREFIX="$(TARGET_DIR)" \
		CC=$(TARGET_CC) \
		all install

qserver-clean:
	-$(MAKE) -C $(QSERVER_BUILD_DIR) clean

qserver-dirclean: qserver-clean

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_QSERVER)),y)
TARGETS+=qserver
endif
