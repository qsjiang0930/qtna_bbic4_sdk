#############################################################
#
# Quantenna - include qtn build artefacts inside a parent image
#
#############################################################

define copy_fw
	mkdir -p ${TARGET_DIR}/$2/
	for file in $1 ; do							\
		test -f $$file || exit 1 ;					\
		tg=${TARGET_DIR}/$2/`basename $$file` ;				\
		cp $$file $$tg && chmod 444 $$tg ;				\
		if [ "$3" = "md5" ] ; then					\
			rm -rf $$tg.md5 ;					\
			md5sum $$file |  sed 's#/# #g' |			\
				awk '{print $$1"  $2/"$$NF}'>  $$tg.md5 ;	\
			chmod 444 $$tg.md5 ;					\
		fi								\
	done
endef

QTN_DISTRIBUTION:="Distributed in binary only. Includes 3-d party components, see COPYING and refer to description for each individual component."

#############################################################
# Firmware relevant to current build

qtn_macfw:
	$(call copy_fw,$(QTN_FW_STAGING)/qtn_driver.*.bin,/etc/firmware)

qtn_dspfw:
	$(call copy_fw,$(QTN_FW_STAGING)/rdsp_driver.*.bin,/etc/firmware)

ifeq ($(strip $(BR2_PACKAGE_QTN_LINUX_IMG)),y)
CHILD_FW_STAGING := $(CHILD_BUILD_PATH)/$(QTN_FW_STAGING_REL)/$(BR2_PACKAGE_QTN_LINUX_IMG_CONFIG)
endif

qtn_uboot_ep:
ifeq ($(QTN_LINUX_IMG_DIR),)
	$(call copy_fw,$(CHILD_FW_STAGING)/u-boot.bin,/etc/firmware/ep,md5)
else
	$(call copy_fw,$(QTN_LINUX_IMG_DIR)/u-boot.bin,/etc/firmware/ep,md5)
endif

qtn_uboot:
	$(call copy_fw,$(QTN_FW_STAGING)/$(board_config)/u-boot.bin,/etc/firmware,md5)

qtn_aucfw:
	$(call copy_fw,$(QTN_FW_STAGING)/auc_driver.*.bin,/etc/firmware)

qtn_prepopulate:
	# Prepopulating target rootfs with files...
	rsync -auv ../prepopulate/* ${TARGET_DIR}/

define copy_updater
	rm -f $1.update.sh
	make -f ../host/utilities/create_fwupdate_sh.mk $1.update.sh
	$(call copy_fw,$1.update.sh,/etc/firmware)
endef

qtn_uboot_updater:
	$(call copy_updater,../u-boot/u-boot.bin)

qtn_mini_uboot_updater:
	$(call copy_updater,../u-boot/u-boot-mini-piggy.bin)

ifeq ($(strip $(BR2_PACKAGE_QTN_MACFW)),y)
TARGETS += qtn_macfw
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_DSPFW)),y)
TARGETS += qtn_dspfw
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_UBOOT)),y)
TARGETS += qtn_uboot
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_AUCFW)),y)
TARGETS += qtn_aucfw
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_UBOOT_UPGRADE_SCRIPT)),y)
TARGETS += qtn_uboot_updater
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_PREPOPULATE)),y)
TARGETS += qtn_prepopulate
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_MINI_UBOOT_UPGRADE_SCRIPT)),y)
TARGETS += qtn_mini_uboot_updater
endif

#############################################################
# Firmware relevant to child build
CHILD_BUILD_PATH ?= ..

qtn_linux_image:
ifeq ($(QTN_LINUX_IMG_DIR),)
	$(call copy_fw,$(CHILD_FW_STAGING)/$(board_platform)-linux.lzma.img,/etc/firmware/ep)
else
	$(call copy_fw,$(QTN_LINUX_IMG_DIR)/$(board_platform)-linux.lzma.img,/etc/firmware/ep)
endif

ifeq ($(strip $(BR2_PACKAGE_QTN_LINUX_IMG)),y)
TARGETS += qtn_linux_image
TARGETS += qtn_uboot_ep
endif

