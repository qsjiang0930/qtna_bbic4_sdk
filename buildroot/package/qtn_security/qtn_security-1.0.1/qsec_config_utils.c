/*
 * Copyright (c) 2015 Quantenna Communications Inc
 *
 * This software may be distributed under the terms of the BSD license.
 * See the COPYING file for license terms.
 *
 * Configuration parsing code is based on hostapd configuration file parser
 * Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "qsec_utils.h"

#define QSEC_MAX_CONFIG_LINE_LEN	512

const char *qsec_bss_config_param_names[QSEC_BSS_CONFIG_FILES_NUM] = {
	[QSEC_BSS_CONFIG_FILE_DENY_MAC] = "deny_mac_file",
	[QSEC_BSS_CONFIG_FILE_ACCEPT_MAC] = "accept_mac_file",
	[QSEC_BSS_CONFIG_FILE_ACCEPT_OUI] = "accept_oui_file",
};

char *qsec_get_qtn_security_path(void)
{
	FILE *fd;
	char *ret_path = NULL;
	char base_file_path_config[QTN_FILE_PATH_CONFIG_SIZE];
	char *tmpaddr = &base_file_path_config[QTN_FILE_PATH_CONFIG_MAGIC_OFFSET];
	size_t length;

	fd = fopen(QTN_FILE_PATH_CONFIG_FILE, "r");

	if (fd) {
		if (fread(base_file_path_config, 1, sizeof(base_file_path_config), fd) <= 0)
			goto out;

		if (strncmp(QTN_SECURITY_FILE_PATH_TOKEN, tmpaddr,
				strlen(QTN_SECURITY_FILE_PATH_TOKEN)) != 0)
			goto out;

		tmpaddr += strlen(QTN_SECURITY_FILE_PATH_TOKEN);
		base_file_path_config[QTN_FILE_PATH_CONFIG_SIZE - 1] = '\0';

		while (isspace(*tmpaddr) != 0) {
			if (++tmpaddr >= &base_file_path_config[QTN_FILE_PATH_CONFIG_SIZE]) {
				errno = ENAMETOOLONG;
				goto out;
			}
		}

		length = strlen(tmpaddr);

		if (length >= ((size_t)(&base_file_path_config[QTN_FILE_PATH_CONFIG_SIZE] - tmpaddr) - 1)) {
			errno = ENAMETOOLONG;
			goto out;
		}

		if (tmpaddr[length - 1] != '/') {
			tmpaddr[length] = '/';
			tmpaddr[length + 1] = '\0';
		}

		ret_path = strdup(tmpaddr);
	}

out:
	if (fd)
		fclose(fd);

	if (!ret_path)
		ret_path = strdup(QTN_SECURITY_FILE_PATH_DEFAULT);

	return ret_path;
}

char *qsec_lookup_security_param(const char *config_path, const char *if_name, const char *param)
{
	FILE *config_fh;
	char buf[QSEC_MAX_CONFIG_LINE_LEN];
	char *pos;
	int bss_found = 0;
	char *ret = NULL;

	config_fh = fopen(config_path, "r");
	if (!config_fh)
		return NULL;

	while (fgets(buf, sizeof(buf), config_fh)) {
		if (buf[0] == '#')
			continue;

		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}

		if (buf[0] == '\0')
			continue;

		pos = strchr(buf, '=');
		if (pos == NULL)
			continue;

		*pos = '\0';
		pos++;

		if (bss_found) {
			if (!strcmp(buf, param)) {
				ret = strdup(pos);
				break;
			} else if (!strcmp(buf, "interface") || !strcmp(buf, "bss")) {
				/* Section for next BSS started */
				break;
			}
		} else if (!strcmp(buf, "interface") || !strcmp(buf, "bss")) {
			if (!strcmp(pos, if_name))
				bss_found = 1;
		}
	}

	fclose(config_fh);
	return ret;
}

int qsec_update_security_param(const char *config_path,
		const char *if_name, const char *param, const char *val)
{
	FILE *config_fh = NULL;
	FILE *tmp_fh = NULL;
	char buf[QSEC_MAX_CONFIG_LINE_LEN];
	char *buf_dup;
	char *pos;
	char *tmp_path;
	int bss_found = 0;
	int param_updated = 0;
	size_t curr_line_len;
	int ret = -1;

	tmp_path = qsec_get_tmp_file_path(config_path);
	if (tmp_path == NULL)
		return -1;

	tmp_fh = fopen(tmp_path, "w");
	if (!tmp_fh)
		goto out;

	config_fh = fopen(config_path, "r");
	if (!config_fh)
		goto out;

	while (fgets(buf, sizeof(buf), config_fh)) {
		buf_dup = strdup(buf);
		if (!buf_dup)
			goto out;

		if (param_updated || (buf[0] == '#'))
			goto write_line;

		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}

		if (buf[0] == '\0')
			goto write_line;

		pos = strchr(buf, '=');
		if (pos == NULL)
			goto write_line;

		*pos = '\0';
		pos++;

		if (bss_found) {
			if (!strcmp(buf, param)) {
				free(buf_dup);

				if (strcmp(pos, val) != 0) {
					if (fprintf(tmp_fh, "%s=%s\n", param, val) <= 0)
						goto out;

					param_updated = 1;
					continue;
				} else {
					break;
				}
			} else if (!strcmp(buf, "interface") || !strcmp(buf, "bss")) {
				/* Next BSS section started and parameter is still not found */
				free(buf_dup);
				break;
			}
		} else if (!strcmp(buf, "interface") || !strcmp(buf, "bss")) {
			if (!strcmp(pos, if_name))
				bss_found = 1;
		}

write_line:
		curr_line_len = strlen(buf_dup);

		if (fwrite(buf_dup, 1, curr_line_len, tmp_fh) != curr_line_len)
			goto out;

		free(buf_dup);
	}

	if (param_updated) {
		if (rename(tmp_path, config_path) != 0) {
			param_updated = 0;
			goto out;
		}
	}

	ret = 0;
out:
	if (config_fh)
		fclose(config_fh);
	if (tmp_fh)
		fclose(tmp_fh);
	if (!param_updated)
		unlink(tmp_path);

	free(tmp_path);
	return ret;
}
