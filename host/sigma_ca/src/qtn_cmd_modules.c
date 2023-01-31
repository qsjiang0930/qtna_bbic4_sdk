/****************************************************************************
*
* Copyright (c) 2017  Quantenna Communications, Inc.
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
* USE OR PERFORMANCE OF THIS SOFTWARE.
*
*****************************************************************************/

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "qtn_cmd_modules.h"
#include "qtn_ap_handler.h"
#include "qtn_hs2_handler.h"
#include "qtn_sta_handler.h"

struct qtn_module {
	const char *name;
	const struct qtn_cmd_handler* (*lookup_func)(const char *cmd, int len);
};

static
const struct qtn_module qtn_registered_modules[] = {
	{"ap", qtn_lookup_ap_handler },
	{"hs2", qtn_lookup_hs2_handler },
	{"sta", qtn_lookup_sta_handler },
};


#define N_ARRAY(arr)			(sizeof(arr)/sizeof(arr[0]))

const struct qtn_cmd_handler* qtn_lookup_registered_handler(const char *cmd, int len)
{
	int i;

	if (cmd && *cmd && (len > 0)) {
		for (i = 0; i < N_ARRAY(qtn_registered_modules); i++) {
			const struct qtn_module *mod = &qtn_registered_modules[i];
			if (mod->lookup_func != NULL) {
				const struct qtn_cmd_handler* handler = mod->lookup_func(cmd, len);
				if (handler && (handler->func != NULL))
					return handler;

			}
		}
	}

	return NULL;
}
