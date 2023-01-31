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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "qtn_cmd_parser.h"
#include "qtn_cmd_modules.h"
#include "qtn_log.h"

#define N_ARRAY(arr)			(sizeof(arr)/sizeof(arr[0]))

struct qtn_item {
	const int item_id;
	const char *item_text;
};

static
const struct qtn_item qtn_resp_status_table[] = {
	{STATUS_RUNNING,  "RUNNING"},
	{STATUS_INVALID,  "INVALID"},
	{STATUS_ERROR,    "ERROR"},
	{STATUS_COMPLETE, "COMPLETE"},
};

struct qtn_pattern {
	const char* text;
	const int len;
};

#define QTN_MIN_CMD_LENGTH	8

static
const struct qtn_pattern qtn_pattern_table[] = {
	{"AP_",     3},
	{"STA_",    4},
	{"CA_",     3},
	{"DEVICE_", 7},
	{"DEV_",    4},
};


const struct qtn_item *qtn_lookup_item_by_id(const int id, const struct qtn_item *table, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (table[i].item_id == id)
			return &table[i];
	}

	return NULL;
}


static
int qtn_parse_params(const char *params_ptr, struct qtn_cmd_param *param_tab_ptr,
		int param_tab_size, int *error_count)
{
	const char *delim;
	const char *name_ptr;
	int name_len;
	const char *val_ptr;
	int val_len;
	enum qtn_token token;
	struct qtn_cmd_param *param;
	int param_count = 0;
	int err_count = 0;
	const char *pair = params_ptr;

	while (pair && *pair && (param_count < param_tab_size)) {
		delim = strchr(pair, ',');

		if (!delim)
			break;

		name_ptr = pair;
		name_len = delim - pair;
		val_ptr = delim + 1;

		delim = strchr(val_ptr, ',');

		if (delim) {
			val_len = delim - val_ptr;
			pair = delim + 1;
		} else {
			val_len = strlen(val_ptr);
			pair = NULL;
		}

		while ((name_ptr[0] == ' ') && (name_len > 0)) {
			name_ptr++;
			name_len--;
		}

		if (name_len == 0) {
			err_count++;
			break;
		}

		while ((name_len > 0) && (name_ptr[name_len - 1] == ' ')) {
			name_len--;
		}

		/* remove left/right spaces for value */
		while ((val_ptr[0] == ' ') && (val_len > 0)) {
			val_ptr++;
			val_len--;
		}

		while ((val_len > 0) && (val_ptr[val_len - 1] == ' ')) {
			val_len--;
		}

		token = qtn_lookup_token_by_name(name_ptr, name_len);

		if (token) {
			param = &param_tab_ptr[param_count];
			param->key_tok = token;
			param->val_pos = val_ptr - params_ptr;
			param->val_len = val_len;

			param_count++;
		} else
			err_count++;
	}

	if (error_count)
		*error_count = err_count;

	return param_count;
}

static
int qtn_parse_cmd_encode_request(const char *cmd_text, char *buf_ptr, int buf_size)
{
	const char *delim;
	const char *name_ptr;
	int name_len;
	const struct qtn_cmd_handler *handler;
	const char *params;
	struct qtn_cmd_param param_tab[QTN_CMD_MAX_PARAM_COUNT];
	int param_count;
	int error_count;
	int buf_len = 0;
	int i;
	char key_buf[16];
	int key_len;

	/* recognize command name */
	delim = strchr(cmd_text, ',');
	name_len = (delim) ? (delim - cmd_text) : strlen(cmd_text);
	name_ptr = cmd_text;

	while ((name_ptr[0] == ' ') && (name_len > 0)) {
		name_ptr++;
		name_len--;
	}

	if (name_len == 0) {
		return -EINVAL;
	}

	while ((name_len > 0) && (name_ptr[name_len - 1] == ' ')) {
		name_len--;
	}

	handler = qtn_lookup_registered_handler(name_ptr, name_len);

	if (!handler || !handler->func) {
		qtn_log("handler not registered\n");
		return -EINVAL;
	}

	/* copy command header: "CMD#NAME," */
	if (buf_size > (buf_len + 4 + name_len + 1)) {
		strncpy(buf_ptr + buf_len, "CMD#", 4);
		buf_len += 4;
		strncpy(buf_ptr + buf_len, name_ptr, name_len);
		buf_len += name_len;
		/* comma is mandatory */
		buf_ptr[buf_len] = ',';
		buf_len++;
	} else
		return -ENOMEM;

	/* parse and encode parameters */
	params = (delim) ? (delim + 1) : NULL;
	param_count = qtn_parse_params(params, param_tab, N_ARRAY(param_tab), &error_count);

	for (i = 0; i < param_count; i++) {
		struct qtn_cmd_param *param = &param_tab[i];

		key_len = snprintf(key_buf, sizeof(key_buf), "%03d", (int)param->key_tok);

		if (key_len > 0) {
			if (buf_size > (buf_len + key_len + 1 + param->val_len + 1)) {
				strncpy(buf_ptr + buf_len, key_buf, key_len);
				buf_len += key_len;

				buf_ptr[buf_len] = ',';
				buf_len++;

				strncpy(buf_ptr + buf_len, params + param->val_pos, param->val_len);
				buf_len += param->val_len;

				buf_ptr[buf_len] = ',';
				buf_len++;
			} else
				return -ENOMEM;
		}
	}

	/* tail */
	if (buf_size > (buf_len + 2)) {
		buf_ptr[buf_len] = '\r';
		buf_len += 1;
		buf_ptr[buf_len] = '\n';
		buf_len += 1;
	} else
		return -ENOMEM;

	buf_ptr[buf_len] = 0;

	return buf_len;
}


static
int qtn_recognize_command(const char *buf_ptr, const int buf_size)
{
	int pos;

	if (!buf_ptr || (buf_size < QTN_MIN_CMD_LENGTH))
		return -1;

	for (pos = 0; pos < buf_size - QTN_MIN_CMD_LENGTH; pos++) {
		int i;
		for (i = 0; i < N_ARRAY(qtn_pattern_table); i++) {
			const struct qtn_pattern *pat = &qtn_pattern_table[i];
			if (strncasecmp(buf_ptr + pos, pat->text, pat->len) == 0)
				return pos;
		}
	}

	return -1;
}


int qtn_recognize_and_parse_command(const char *cmd_text, char *buf_ptr, int buf_size)
{
	int req_len = -1;
	int cmd_start = qtn_recognize_command(cmd_text, strlen(cmd_text));

	if (cmd_start >= 0)
		req_len = qtn_parse_cmd_encode_request(cmd_text + cmd_start, buf_ptr, buf_size);

	return req_len;
}


static
const char* qtn_search_char(const char *start, const char *end, const char c)
{
	while (start < end) {
		if (*start == c)
			return start;
		start++;
	}

	return NULL;
}


static
int qtn_parse_request(const char *req_ptr, int req_len, struct qtn_cmd_param *param_tab_ptr,
		int param_tab_size, int *error_count)
{
	const char *delim;
	const char *name_ptr;
	int name_len;
	const char *val_ptr;
	int val_len;
	char key_buf[8];
	long key_tok;
	struct qtn_cmd_param *param;
	int param_count = 0;
	int err_count = 0;
	const char *pair = req_ptr;
	const char *req_end = req_ptr + req_len;

	while (pair && (pair < req_end) && (param_count < param_tab_size)) {
		delim = qtn_search_char(pair, req_end, ',');

		if (!delim)
			break;

		name_ptr = pair;
		name_len = delim - pair;
		val_ptr = delim + 1;

		delim = qtn_search_char(val_ptr, req_end, ',');

		if (delim) {
			val_len = delim - val_ptr;
			pair = delim + 1;
		} else {
			val_len = req_end - val_ptr;
			pair = NULL;
		}

		if ((name_len <= 0) || (name_len >= sizeof(key_buf))) {
			err_count++;
			break;
		}

		strncpy(key_buf, name_ptr, name_len);
		key_buf[name_len] = 0;

		key_tok = strtol(key_buf, NULL, 10);

		if ((key_tok == 0) || (key_tok == LONG_MAX) || (key_tok == LONG_MIN)) {
			err_count++;
			break;
		}

		param = &param_tab_ptr[param_count];
		param->key_tok = (enum qtn_token)key_tok;
		param->val_pos = val_ptr - req_ptr;
		param->val_len = val_len;

		param_count++;
	}

	if (error_count)
		*error_count = err_count;

	return param_count;
}


int qtn_dispatch_request(const char* cmd_req, char* resp_buf, int resp_size)
{
	const char *delim;
	int hdr_len;
	const struct qtn_cmd_handler *handler = NULL;
	const char *params;
	int params_len;
	struct qtn_response resp;
	int resp_len;


	if (!cmd_req || (cmd_req[0] == 0) || !resp_buf || (resp_size <= 0))
		return -EINVAL;

	/* recognize command request: "CMD#NAME,param1,val1," */
	delim = strchr(cmd_req, ',');
	if (!delim)
		return -EINVAL;

	hdr_len = delim - cmd_req;

	if (hdr_len < 4)
		return -EINVAL;

	/* check signature */
	if (memcmp(cmd_req, "CMD#", 4) != 0)
		return -EINVAL;

	/* lookup handler */
	handler = qtn_lookup_registered_handler(cmd_req + 4, hdr_len - 4);

	if (!handler || !handler->func)
		return -EOPNOTSUPP;

	/* run command action */
	params = delim + 1;
	params_len = strlen(params);
	memset(&resp, 0, sizeof(resp));

	handler->func(params, params_len, &resp);

	/* encode response */
	resp_len = qtn_encode_response(&resp, resp_buf, resp_size);

	return resp_len;
}


int qtn_init_cmd_request(struct qtn_cmd_request *cmd_req, const char *req_ptr, int req_len)
{
	if (!cmd_req)
		return -EINVAL;

	if (req_ptr && (req_len > 0)) {
		int error_count;

		cmd_req->param_count = qtn_parse_request((const char*)req_ptr, req_len,
				cmd_req->param_tab, N_ARRAY(cmd_req->param_tab),
				&error_count);

		cmd_req->req_ptr = req_ptr;
		cmd_req->req_len = req_len;
	} else {
		cmd_req->param_count = 0;
		cmd_req->req_ptr = NULL;
		cmd_req->req_len = 0;
	}

	return 0;
}

static
int qtn_get_value(const struct qtn_cmd_request *cmd_req, enum qtn_token tok, const char **val_ptr,
	int *val_len)
{
	int i;
	const struct qtn_cmd_param *param;

	if (!cmd_req)
		return -EINVAL;

	for (i = 0; i < cmd_req->param_count; i++) {
		param = &cmd_req->param_tab[i];

		if (param->key_tok == tok) {
			*val_ptr = cmd_req->req_ptr + param->val_pos;
			*val_len = param->val_len;
			return 0;
		}
	}

	return -ENODATA;
}

int qtn_get_value_text(const struct qtn_cmd_request *cmd_req, enum qtn_token tok, char *buf_ptr,
	int buf_size)
{
	const char *val_ptr;
	int val_len;
	int ret;

	if (!buf_ptr || (buf_size <= 0))
		return -EINVAL;

	ret = qtn_get_value(cmd_req, tok, &val_ptr, &val_len);

	if (ret != 0)
		return ret;

	if (val_len >= buf_size)
		return -ENOMEM;

	if (val_len > 0)
		strncpy(buf_ptr, val_ptr, val_len);

	buf_ptr[val_len] = 0;

	return val_len;
}

int qtn_get_value_int(const struct qtn_cmd_request *cmd_req, enum qtn_token tok, int *value)
{
	const char *val_ptr;
	int val_len;
	char val_buf[32];
	int ret;

	if (!value)
		return -EINVAL;

	ret = qtn_get_value(cmd_req, tok, &val_ptr, &val_len);

	if (ret != 0)
		return ret;

	if (val_len >= sizeof(val_buf))
		return -ENOMEM;

	if (val_len > 0) {
		strncpy(val_buf, val_ptr, val_len);
		val_buf[val_len] = 0;
		*value = strtol(val_buf, NULL, 10);
	}

	return val_len;
}

/*
 * return Enable/Disable value
 */
int qtn_get_value_enable(const struct qtn_cmd_request *cmd_req, enum qtn_token tok, int *enable,
	int *conv_error)
{
	const char *val_ptr;
	int val_len;
	char val_buf[32];
	int ret;

	if (conv_error)
		*conv_error = 0;

	if (!enable)
		return -EINVAL;

	ret = qtn_get_value(cmd_req, tok, &val_ptr, &val_len);

	if (ret != 0)
		return ret;

	if (val_len >= sizeof(val_buf))
		return -EINVAL;

	if (val_len > 0) {
		strncpy(val_buf, val_ptr, val_len);
		val_buf[val_len] = 0;

		if (strcasecmp(val_buf, "Enable") == 0)
			*enable = 1;
		else if (strcasecmp(val_buf, "Disable") == 0)
			*enable = 0;
		else {
			/* complain about unrecognized value */
			val_len = -EINVAL;

			if (conv_error)
				*conv_error = -EINVAL;
		}
	}

	return val_len;
}


int qtn_encode_response(struct qtn_response *resp, char *buf_ptr, int buf_size)
{
	const struct qtn_item *resp_item;
	int resp_len;

	resp_item = qtn_lookup_item_by_id(resp->status,
			qtn_resp_status_table, N_ARRAY(qtn_resp_status_table));
	if (!resp_item)
		return -EINVAL;

	if (((resp->status == STATUS_INVALID) || (resp->status == STATUS_ERROR))
			&& (resp->error_code)) {
		resp_len = snprintf(buf_ptr, buf_size, "status,%s,errorCode,%d",
				resp_item->item_text, resp->error_code);
	} else {
		resp_len = snprintf(buf_ptr, buf_size, "status,%s",
				resp_item->item_text);
	}

	if (resp_len < 0)
		return -ENOMEM;

	/* additional parameters */
	if (resp->param_buf[0] && (buf_size > (resp_len + strlen(resp->param_buf) + 1))) {
		int len = snprintf(buf_ptr + resp_len, buf_size - resp_len, ",%s", resp->param_buf);
		if (len < 0)
			return -ENOMEM;

		resp_len += len;
	}

	/* tail */
	if (buf_size > (resp_len + 2)) {
		buf_ptr[resp_len] = '\r';
		resp_len += 1;
		buf_ptr[resp_len] = '\n';
		resp_len += 1;
	} else
		return -ENOMEM;

	buf_ptr[resp_len] = 0;

	return resp_len;
}


int qtn_encode_response_status(enum qtn_response_status status, int error_code,
		char *buf_ptr, int buf_size)
{
	struct qtn_response resp;
	resp.status = status;
	resp.error_code = error_code;
	resp.param_buf[0] = 0;

	return qtn_encode_response(&resp, buf_ptr, buf_size);
}


const struct qtn_cmd_handler * qtn_lookup_cmd_handler(const char *cmd, int len,
		const struct qtn_cmd_handler *table, int count)
{
	int i;

	if (cmd && *cmd && (len > 0)) {
		for (i = 0; i < count; i++) {
			if (table[i].cmd && (strncasecmp(table[i].cmd, cmd, len) == 0))
				if (strlen(table[i].cmd) == len)
					return &table[i];
		}
	}

	return NULL;
}
