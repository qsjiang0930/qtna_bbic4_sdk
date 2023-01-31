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

#ifndef QTN_CMD_PARSER_H_
#define QTN_CMD_PARSER_H_

#include "qtn_cmd_tokens.h"

struct qtn_cmd_param {
	enum qtn_token key_tok;
	int val_pos;
	int val_len;
};

#define QTN_CMD_MAX_PARAM_COUNT		32

struct qtn_cmd_request {
	struct qtn_cmd_param param_tab[QTN_CMD_MAX_PARAM_COUNT];
	int param_count;
	const char *req_ptr;
	int req_len;
};

enum qtn_response_status
{
       STATUS_RUNNING = 0x0001,
       STATUS_INVALID = 0x0002,
       STATUS_ERROR = 0x0003,
       STATUS_COMPLETE = 0x0004,
};

#define QTN_RESP_PARAM_BUFSIZE		512

struct qtn_response {
	enum qtn_response_status status;
	int error_code;
	char param_buf[QTN_RESP_PARAM_BUFSIZE];
};

struct qtn_cmd_handler {
	const char *cmd;
	void (*func) (const char *params, int len, struct qtn_response *resp);
};


int qtn_init_cmd_request(struct qtn_cmd_request *cmd_req, const char *req_ptr, int req_len);
int qtn_get_value_text(const struct qtn_cmd_request *cmd_req, enum qtn_token tok,
		char *buf_ptr, int buf_size);
int qtn_get_value_int(const struct qtn_cmd_request *cmd_req, enum qtn_token tok,
		int *value);
int qtn_get_value_enable(const struct qtn_cmd_request *cmd_req, enum qtn_token tok,
		int *enable, int *conv_error);

int qtn_recognize_and_parse_command(const char *cmd_text, char *buf_ptr, int buf_size);
int qtn_dispatch_request(const char* cmd_req, char* resp_buf, int resp_size);
int qtn_encode_response(struct qtn_response *resp, char *buf_ptr, int buf_size);
int qtn_encode_response_status(enum qtn_response_status status, int error_code,
		char *buf_ptr, int buf_size);

const struct qtn_cmd_handler * qtn_lookup_cmd_handler(const char *cmd, int len,
		const struct qtn_cmd_handler *table, int count);


#endif	/* QTN_CMD_PARSER_H_ */
