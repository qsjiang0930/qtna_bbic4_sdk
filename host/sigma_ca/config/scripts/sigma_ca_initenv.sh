#!/bin/sh

conf_default_path=/etc/default

if [ -e "${conf_default_path}/nvram" ]; then
	. "${conf_default_path}/nvram"
fi

conf_images_path=/usr/share/images/sigma_ca

# first parameter is name of configuration
conf_name=$1

sigma_ca_exec=/usr/sbin/qtn_sigma_ca

