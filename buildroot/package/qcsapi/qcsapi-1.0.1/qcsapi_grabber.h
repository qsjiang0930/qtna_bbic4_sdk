/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 */
#ifndef _QCSAPI_GRABBER_H
#define _QCSAPI_GRABBER_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <qcsapi.h>

#define QCSAPI_GRABBER_PARAM_ALL UINT32_MAX

extern int qcsapi_grabber_write_config_blob(FILE *s, uint32_t param_num, size_t *bytes_written);
#endif /* _QCSAPI_GRABBER_H */
