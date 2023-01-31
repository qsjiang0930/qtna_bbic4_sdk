/*
 * Copyright (c) 2015 Quantenna Communications Inc
 *
 * This software may be distributed under the terms of the BSD license.
 * See the COPYING file for license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "qsec_utils.h"

#define QSEC_TEMPORARY_SUFFIX		".hapr.tmp"
/* Size doesn't matter: smaller sizes will just cause more cp iteratons */
#define QSEC_FILE_CP_BUF_SIZE		256

int qsec_write_file(const char *buff, const char *path)
{
	FILE *f;
	int len = strlen(buff);
	char *tmp_path = qsec_get_tmp_file_path(path);
	int ret = -1;

	if (!tmp_path)
		return -1;

	f = fopen(tmp_path, "w");
	if (f == NULL)
		goto out;

	if (fwrite(buff, 1, len, f) != len) {
		fclose(f);
		unlink(tmp_path);
		goto out;
	}

	fclose(f);

	if (rename(tmp_path, path) != 0) {
		unlink(tmp_path);
		goto out;
	}

	ret = 0;

out:
	free(tmp_path);
	return ret;
}

void *qsec_alloc_n_read_file(const char *fpath, unsigned content_offset, unsigned int *cmd_len_ret)
{
	FILE *f;
	long int len;
	long int full_len;
	char *content = NULL;

	f = fopen(fpath, "r");
	if (f == NULL)
		return NULL;

	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (len < 0)
		goto out;

	full_len = len + content_offset + 1;

	content = malloc(full_len);
	if (!content)
		goto out;

	if (fread(content + content_offset, 1, len, f) != len) {
		free(content);
		content = NULL;
		goto out;
	}

	content[full_len - 1] = '\0';
	if (cmd_len_ret)
		*cmd_len_ret = full_len;

out:
	fclose(f);
	return content;
}

static int qsec_copy_file_content(FILE *dst_fd, FILE *src_fd)
{
	size_t bytes_read;
	char buf[QSEC_FILE_CP_BUF_SIZE];

	do {
		bytes_read = fread(buf, 1, sizeof(buf), src_fd);
		if (ferror(src_fd) != 0)
			return -1;

		if (bytes_read && (fwrite(buf, 1, bytes_read, dst_fd) != bytes_read))
			return -1;
	} while (bytes_read == sizeof(buf));

	return 0;
}

char *qsec_get_tmp_file_path(const char *file_path)
{
	char *tmp_path = malloc(strlen(file_path) + strlen(QSEC_TEMPORARY_SUFFIX) + 1);

	if (tmp_path) {
		strcpy(tmp_path, file_path);
		strcat(tmp_path, QSEC_TEMPORARY_SUFFIX);
	}

	return tmp_path;
}

int qsec_concat_files(const char *dst_file, const char *src_file)
{
	FILE *dst_fd = NULL;
	FILE *src_fd = NULL;
	FILE *tmp_fd = NULL;
	char *tmp_path;
	int ret = -1;

	tmp_path = qsec_get_tmp_file_path(dst_file);
	if (tmp_path == NULL)
		return -1;

	dst_fd = fopen(dst_file, "r");
	if (dst_fd == NULL)
		goto out;

	src_fd = fopen(src_file, "r");
	if (src_fd == NULL)
		goto out;

	tmp_fd = fopen(tmp_path, "w");
	if (tmp_fd == NULL)
		goto out;

	if (qsec_copy_file_content(tmp_fd, dst_fd))
		goto out;

	if (fputc('\n', tmp_fd) == EOF)
		goto out;

	if (qsec_copy_file_content(tmp_fd, src_fd))
		goto out;

	fclose(tmp_fd);
	tmp_fd = NULL;

	if (rename(tmp_path, dst_file) != 0)
		goto out;

	ret = 0;

out:
	if (dst_fd)
		fclose(dst_fd);

	if (src_fd)
		fclose(src_fd);

	if (tmp_fd) {
		fclose(tmp_fd);
		unlink(tmp_path);
	}

	free(tmp_path);
	return ret;
}

int qsec_check_file_exists(const char *file_path)
{
	int ret = 0;
	FILE *f = fopen(file_path, "r");

	if (f) {
		ret = 1;
		fclose(f);
	}

	return ret;
}

int qsec_write2_qdrv_control(const char *cmd)
{
	FILE *qdrv_control;
	int ret;

	qdrv_control = fopen(QTN_DRV_CONTROL_FILE, "w");
	if (!qdrv_control)
		return -1;

	ret = fwrite(cmd, strlen(cmd), 1, qdrv_control);
	fclose(qdrv_control);

	if (!ret)
		return -1;

	return 0;
}
