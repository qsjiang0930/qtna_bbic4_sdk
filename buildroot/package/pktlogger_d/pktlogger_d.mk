# (C)2016 Quantenna Communications Inc.


.PHONY: FORCE

PKTLOGGER_D_DIR=$(TOPDIR)/package/pktlogger_d

PKTLOGGER_D_BUILD_DIR=$(PKTLOGGER_D_DIR)/pktlogger_d/
EXTRA_WARNINGS= -Wall -Wshadow -Werror

export PKTLOGGER_D_BUILD_DIR TARGET_DIR

# Dependency on q_event to build/install ql2t
pktlogger_d: q_event
	$(MAKE) -C $(PKTLOGGER_D_BUILD_DIR) CC=$(TARGET_CC) install

pktlogger_d-clean:
	-$(MAKE) -C $(PKTLOGGER_D_BUILD_DIR) clean

pktlogger_d-distclean: pktlogger_d-clean
	rm -f $(TARGET_DIR)/usr/sbin/pktlogger_d

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_PKTLOGGER_D)),y)
TARGETS+=pktlogger_d
endif
