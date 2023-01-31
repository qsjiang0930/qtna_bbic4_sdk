#############################################################
#
# QTM
#
#############################################################
QTM_SOURCE=qtm.tar.gz
QTM_SITE=ftp://ftp.quantenna.com
TOPDIR:=$(shell readlink -f $(TOPDIR))
QTM_MK_DIR=$(TOPDIR)/package/qtm
QTM_DIR=$(QTM_MK_DIR)/src

QTN_DISTRIBUTION:="Distributed as binary only user executable"

#Do not use dependencies for this target, because they are executed even if
#this target exists and appears as order-only prerequisite of another target.
#Target's handler isn't executed in this case.
$(QTM_DIR):
	test -f $(DL_DIR)/$(QTM_SOURCE) || \
		$(WGET) -P $(DL_DIR) $(QTM_SITE)/$(QTM_SOURCE)
	$(ZCAT) $(DL_DIR)/$(QTM_SOURCE) | tar -C $(QTM_MK_DIR) $(TAR_OPTIONS) -
	test -d $(QTM_DIR) || \
		mv $(QTM_MK_DIR)/qtm $(QTM_DIR)

qtm: libnl3 | $(QTM_DIR)
	$(MAKE) -C $(BASE_DIR)/package/qtm/src \
		CROSS_COMPILE=$(TARGET_CROSS) TARGET_DIR=$(TARGET_DIR) STAGING_DIR=$(STAGING_DIR) install
	install -d $(TARGET_DIR)/bin

qtm-clean:
	$(MAKE) -C $(BASE_DIR)/package/qtm/src TARGET_DIR=$(TARGET_DIR) clean

qtm-dirclean:

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_QTM)),y)
TARGETS+=qtm
endif
