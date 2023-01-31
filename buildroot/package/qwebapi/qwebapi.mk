#############################################################
#
# QWEBAPI
#
#############################################################

ifndef board_config
-include $(BASE_DIR)/../board_config.mk
endif

QWEBAPI_DIR=${shell ls $(BASE_DIR)/package/qwebapi/* -dF | grep '/$$'}

#qwebapi: qwcfg
qwebapi:
ifneq ($(strip $(QWEBAPI_DIR)),)
	$(MAKE) -C $(QWEBAPI_DIR) ARCH=arc TARGET_CROSS=$(TARGET_CROSS) STAGING_DIR=$(STAGING_DIR) TARGET_DIR=$(TARGET_DIR) BUILD_DIR=$(BUILD_DIR) all install
endif

qwebapi-clean:
ifneq ($(strip $(QWEBAPI_DIR)),)
	$(MAKE) -C $(QWEBAPI_DIR) ARCH=arc CROSS_COMPILE=$(TARGET_CROSS) TARGET_DIR=$(TARGET_DIR) clean
endif

qwebapi-distclean:
ifneq ($(strip $(QWEBAPI_DIR)),)
	$(MAKE) -C $(QWEBAPI_DIR) ARCH=arc CROSS_COMPILE=$(TARGET_CROSS) TARGET_DIR=$(TARGET_DIR) distclean
endif

qwebapi-dirclean:

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_QWEBAPI)),y)
TARGETS+=qwebapi
endif
