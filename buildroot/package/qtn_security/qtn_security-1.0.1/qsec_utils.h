/*
 * Copyright (c) 2015 Quantenna Communications Inc
 *
 * This software may be distributed under the terms of the BSD license.
 * See the COPYING file for license terms.
 */

#ifndef QSEC_CONFIG_PARSER_H
#define QSEC_CONFIG_PARSER_H

#include <stdint.h>

#define QTN_FILE_PATH_CONFIG_FILE		"/proc/bootcfg/filepath.txt"
#define QTN_FILE_PATH_CONFIG_SIZE		1024
#define QTN_CREATE_FILE_PATH_CONFIG		"create filepath.txt 0x400"
#define QTN_FILE_PATH_CONFIG_MAGIC		0x1234
#define QTN_FILE_PATH_CONFIG_MAGIC_OFFSET	sizeof(uint16_t)
#define QTN_SECURITY_FILE_PATH_TOKEN		"security"
#define QTN_SECURITY_FILE_PATH_DEFAULT		"/mnt/jffs2/"
#define QTN_DRV_CONTROL_FILE			"/sys/devices/qdrv/control"

typedef enum {
	QSEC_BSS_CONFIG_FILE_DENY_MAC = 0,
	QSEC_BSS_CONFIG_FILE_ACCEPT_MAC = 1,
	QSEC_BSS_CONFIG_FILE_ACCEPT_OUI = 2,
	QSEC_BSS_CONFIG_FILES_NUM,
} qsec_bss_config_file;

/*
 * Names for per-BSS file path hostapd configuration parameters
 */
extern const char *qsec_bss_config_param_names[QSEC_BSS_CONFIG_FILES_NUM];

/*
 * Returns a directory path on Quantenna filesystem where security configuration should
 * be stored, or NULL if return buffer allocation failed.
 * Returned string shall be freed by a caller.
 */
char *qsec_get_qtn_security_path(void);

/*
 * Look through configuration file specified by 'config_path' for a parameter 'param'
 * corresponding to BSS identified by 'if_name' and (if found) return its value.
 * Value storage is allocated by malloc() and shall be freed by a caller.
 */
char *qsec_lookup_security_param(const char *config_path, const char *if_name, const char *param);

/*
 * Look through configuration file specified by 'config_path' for a parameter 'param' and
 * (if found) replace its value with 'val'.
 * If 'param' does not exist already in configuration file, or if 'param' already
 * has a value equal to "val", then nothing is done and success is indicated to a caller.
 */
int qsec_update_security_param(const char *config_path,
		const char *if_name, const char *param, const char *val);

/*
 * Write content stored in '\0'-terminated 'buff' to file specified by 'path'.
 */
int qsec_write_file(const char *buff, const char *path);

/*
 * Allocates buffer long enough to fit a content of a file specified by "fpath" + content_offset
 * bytes, and reads file content to this buffer starting at offset content_offset.
 * Returns a pointer to allocated buffer or NULL in case of failure.
 * Buffer must be freed by the caller.
 */
void *qsec_alloc_n_read_file(const char *fpath, unsigned content_offset, unsigned int *cmd_len_ret);

/*
 * Allocate buffer of necessary length and construct a path to a temporary file
 * based on 'file_path'. Returned buffer must be freed by a caller.
 */
char *qsec_get_tmp_file_path(const char *file_path);

/*
 * Appends a content of a file specified by 'src_file' to a file specified by 'dst_file'
 */
int qsec_concat_files(const char *dst_file, const char *src_file);

/*
 * Returns '1' if file specified by 'file_path' exists and is accessible.
 * Returns 0 otherwise.
 */
int qsec_check_file_exists(const char *file_path);

/*
 * Write a command contained in buffer pointed by 'cmd' to QDRV driver control interface.
 */
int qsec_write2_qdrv_control(const char *cmd);

#endif
