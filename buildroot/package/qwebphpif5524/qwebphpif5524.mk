#############################################################
#
# Quantenna Web interface for QV864
#
#############################################################

QWEBIF5524_DIR=package/qwebphpif5524

FORCE:

qwebphpif5524: FORCE
	mkdir -p $(TARGET_DIR)/var/www
	cp -r $(QWEBIF5524_DIR)/www/* $(TARGET_DIR)/var/www
	rm -rf $(TARGET_DIR)/var/www/themes/*
	cp $(QWEBIF5524_DIR)/www/themes/style.css $(TARGET_DIR)/var/www/themes/style.css
	chmod -R u+w $(TARGET_DIR)/var/www/*
	mkdir -p $(TARGET_DIR)/usr/lib/cgi-bin
	cp -f $(QWEBIF5524_DIR)/admin.conf $(TARGET_DIR)/etc

qwebphpif5524-clean:

qwebphpif5524-dirclean:

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_QWEBPHPIF5524)),y)
TARGETS+=qwebphpif5524
endif
