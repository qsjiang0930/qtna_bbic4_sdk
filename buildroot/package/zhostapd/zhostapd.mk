#############################################################
#
# hostapd / wpa_supplicant
#
#############################################################
ZHOSTAPD_VERSION=hostapd-latest
ZHOSTAPD_BASE_DIR=$(TOPDIR)/package/zhostapd

HOSTAPD_DIR=$(ZHOSTAPD_BASE_DIR)/$(ZHOSTAPD_VERSION)/hostapd
WPA_SUPPLICANT_DIR=$(ZHOSTAPD_BASE_DIR)/$(ZHOSTAPD_VERSION)/wpa_supplicant


.PHONY: FORCE

#############################################################
# hostapd, hostapd_cli
#############################################################
$(HOSTAPD_DIR)/hostapd: FORCE
	cp -f $(ZHOSTAPD_BASE_DIR)/hostapd.config $(HOSTAPD_DIR)/.config
	$(MAKE) -C $(HOSTAPD_DIR) hostapd CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/hostapd: $(HOSTAPD_DIR)/hostapd
	# Copy hostapd
	cp -af $< $@

hostapd_clean:
	-$(MAKE) -C $(HOSTAPD_DIR) clean

hostapd: hostapd_clean $(TARGET_DIR)/usr/sbin/hostapd

$(HOSTAPD_DIR)/hostapd_cli: FORCE
	cp -f $(ZHOSTAPD_BASE_DIR)/hostapd.config $(HOSTAPD_DIR)/.config
	$(MAKE) -C $(HOSTAPD_DIR) hostapd_cli CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/hostapd_cli: $(HOSTAPD_DIR)/hostapd_cli
	# Copy hostapd_cli
	# cp -af $(HOSTAPD_DIR)/hostapd_cli $(TARGET_DIR)/usr/sbin/
	cp -af $< $@

hostapd_cli: hostapd_clean $(TARGET_DIR)/usr/sbin/hostapd_cli

#############################################################
# wpa_supplicant, wpa_cli, wdskey
#############################################################
$(WPA_SUPPLICANT_DIR)/wpa_supplicant: FORCE
	cp -f $(ZHOSTAPD_BASE_DIR)/wpa_supplicant.config $(WPA_SUPPLICANT_DIR)/.config
	$(MAKE) -C $(WPA_SUPPLICANT_DIR) all CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/wpa_supplicant: $(WPA_SUPPLICANT_DIR)/wpa_supplicant
	# Copy wpa_supplicant
	cp -af $< $@

wpa_supplicant_clean:
	-$(MAKE) -C $(WPA_SUPPLICANT_DIR) clean

wpa_supplicant: wpa_supplicant_clean $(TARGET_DIR)/usr/sbin/wpa_supplicant

$(WPA_SUPPLICANT_DIR)/wpa_cli: FORCE
	cp -f $(ZHOSTAPD_BASE_DIR)/wpa_supplicant.config $(WPA_SUPPLICANT_DIR)/.config
	$(MAKE) -C $(WPA_SUPPLICANT_DIR) wpa_cli CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/wpa_cli: $(WPA_SUPPLICANT_DIR)/wpa_cli
	# Copy wpa_cli
	# cp -af $(WPA_SUPPLICANT_DIR)/wpa_cli $(TARGET_DIR)/usr/sbin/
	cp -af $< $@

$(WPA_SUPPLICANT_DIR)/wdskey: FORCE
	cp -f $(ZHOSTAPD_BASE_DIR)/wpa_supplicant.config $(WPA_SUPPLICANT_DIR)/.config
	$(MAKE) -C $(WPA_SUPPLICANT_DIR) wdskey CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/wdskey: $(WPA_SUPPLICANT_DIR)/wdskey
	# Copy wdskey
	# cp -af $(WPA_SUPPLICANT_DIR)/wdskey $(TARGET_DIR)/usr/sbin/
	cp -af $< $@

wpa_cli: wpa_supplicant_clean $(TARGET_DIR)/usr/sbin/wpa_cli
wdskey: wpa_supplicant_clean $(TARGET_DIR)/usr/sbin/wdskey

#############################################################
# clean and dirclean
#############################################################
zhostapd-clean: hostapd_clean wpa_supplicant_clean

zhostapd-dirclean: zhostapd-clean
	rm -f $(HOSTAPD_DIR)/.config
	rm -f $(WPA_SUPPLICANT_DIR)/.config
	rm -f $(TARGET_DIR)/usr/sbin/hostapd
	rm -f $(TARGET_DIR)/usr/sbin/hostapd_cli
	rm -f $(TARGET_DIR)/usr/sbin/wpa_supplicant
	rm -f $(TARGET_DIR)/usr/sbin/wpa_cli
	rm -f $(TARGET_DIR)/usr/sbin/wdskey


#############################################################
# Toplevel Makefile options
#############################################################
ifeq ($(strip $(BR2_PACKAGE_ZHOSTAPD)),y)
TARGETS+=hostapd
TARGETS+=hostapd_cli
TARGETS+=wpa_supplicant
TARGETS+=wpa_cli
TARGETS+=wdskey
endif
