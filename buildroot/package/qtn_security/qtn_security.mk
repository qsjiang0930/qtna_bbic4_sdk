
.PHONY: qtn_security qtn_security_clean qtn_security_distclean

QSEC_DIR=$(TOPDIR)/package/qtn_security
QSEC_VER:=1.0.1
QSEC_BUILD_DIR=$(QSEC_DIR)/qtn_security-$(QSEC_VER)
QSEC_CFLAGS= -Wall -Wshadow -Werror

qtn_security:
	$(MAKE) -C $(QSEC_BUILD_DIR) PREFIX="$(TARGET_DIR)" \
		LDFLAGS="-L$(TARGET_DIR)/lib" \
		CC=$(TARGET_CC) CFLAGS="$(TARGET_CFLAGS) $(QSEC_CFLAGS)" \
		install

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_QTN_SECURITY)),y)
TARGETS+=qtn_security
endif

qtn_security_clean:
	$(MAKE) -C $(QSEC_BUILD_DIR) clean

qtn_security_distclean: qtn_security_clean

