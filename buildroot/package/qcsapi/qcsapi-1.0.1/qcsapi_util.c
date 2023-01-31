/*SH0
*******************************************************************************
**                                                                           **
**           Copyright (c) 2015 Quantenna Communications, Inc.               **
**                                                                           **
**  File        : qcsapi_util.h                                              **
**  Description : utility functions to be used by qcsapi_* and call_qcsapi   **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "qcsapi_util.h"

/*
 * verify function return negative value when the parameter_value is not valid
 */
int qcsapi_verify_numeric(const char *parameter_value)
{
	while (*parameter_value != '\0') {
		if (!isdigit(*parameter_value))
			return -1;
		parameter_value++;
	}
	return 0;
}

/*
 * Conversion from string to unsigned integer.
 * Handles invalid strings and integer overflows.
 * return:
 *  0 - on success
 *  -1 - on error
 */
int qcsapi_util_str_to_uint32(const char *str, uint32_t *result)
{
	char *endptr = NULL;
	uint32_t res;

	if (str == NULL)
		return -EFAULT;

	while (isspace(*str)) {
		str++;
	}

	if (!isdigit(*str)) {
		return -1;
	}

	errno = 0;
	res = strtoul(str, &endptr, 10);
	if (errno != 0) {
		return -1;
	}

	if (!endptr || endptr == str) {
		return -1;
	}

	while (isspace(*endptr)) {
		endptr++;
	}

	if (*endptr != '\0') {
		return -1;
	}

	*result = res;
	return 0;
}

int qcsapi_util_str_to_int32(const char *str, int32_t *result)
{
	char *endptr;

	if (str == NULL)
		return -EFAULT;

	errno = 0;
	*result = strtol(str, &endptr, 10);
	if (errno != 0)
		return -errno;

	while (isspace(*endptr))
		endptr++;

	if (*endptr != '\0')
		return -EINVAL;

	return 0;
}

int qcsapi_list_to_array32(const char *input_list, uint32_t *output_array,
		const uint32_t max_count, uint32_t *count)
{
	uint32_t cnt = 0;
	int retval = 0;
	const char *delim = ",";
	char *token;
	char *str = strdup(input_list);
	char *rest = str;

	if (!input_list || !output_array || !count)
		retval = -EINVAL;

	if (retval >= 0) {
		while ((token = strtok_r(rest, delim, &rest))) {
			if (cnt >= max_count) {
				retval = -ERANGE;
				break;
			}

			retval = qcsapi_util_str_to_uint32(token, &output_array[cnt++]);

			if (retval != 0)
				break;
		}
	}

	*count = cnt;
	free(str);

	return retval;
}

#define QCSAPI_MAX_ETHER_STRING 17

int parse_mac_addr(const char *mac_addr_as_str, qcsapi_mac_addr mac_addr)
{
	int i;
	int mac_len = strnlen(mac_addr_as_str, QCSAPI_MAX_ETHER_STRING + 1);
	unsigned int tmp[sizeof(qcsapi_mac_addr)];
	int retval;

	if (mac_addr_as_str == NULL)
		return -qcsapi_invalid_mac_addr;

	if (mac_len > QCSAPI_MAX_ETHER_STRING) {
		return -qcsapi_invalid_mac_addr;
	}

	for (i = 0; i < mac_len; i++) {
		if (!(isxdigit(mac_addr_as_str[i]) || (mac_addr_as_str[i] == ':')))
			return -qcsapi_invalid_mac_addr;
	}

	retval = sscanf(mac_addr_as_str, "%x:%x:%x:%x:%x:%x",
			&tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
	if (retval != sizeof(qcsapi_mac_addr))
		return -qcsapi_invalid_mac_addr;

	for (i = 0; i < sizeof(qcsapi_mac_addr); i++) {
		if (tmp[i] > 0xff)
			return -qcsapi_invalid_mac_addr;
	}

	mac_addr[0] = (uint8_t) tmp[0];
	mac_addr[1] = (uint8_t) tmp[1];
	mac_addr[2] = (uint8_t) tmp[2];
	mac_addr[3] = (uint8_t) tmp[3];
	mac_addr[4] = (uint8_t) tmp[4];
	mac_addr[5] = (uint8_t) tmp[5];

	return 0;
}

int validate_mac_addr(const char *mac_addr_as_str)
{
	int i;
	int retval;
	unsigned int tmp[MAC_ADDR_SIZE];
	int mac_len = strnlen(mac_addr_as_str, QCSAPI_MAX_ETHER_STRING + 1);

	if (mac_addr_as_str == NULL)
		return -qcsapi_invalid_mac_addr;

	if (mac_len > QCSAPI_MAX_ETHER_STRING)
		return -qcsapi_invalid_mac_addr;

	for (i = 0; i < mac_len; i++) {
		if (!(isxdigit(mac_addr_as_str[i]) || (mac_addr_as_str[i] == ':')))
			return -qcsapi_invalid_mac_addr;
	}

	retval = sscanf(mac_addr_as_str, "%x:%x:%x:%x:%x:%x",
			&tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
	if (retval != MAC_ADDR_SIZE)
		return -qcsapi_invalid_mac_addr;

	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		if (tmp[i] > 0xff)
			return -qcsapi_invalid_mac_addr;
	}

	return 0;
}

int qcsapi_isspace(char str)
{
	char spaceset[] = {' ', '\n', '\t', '\v', '\f', '\r', '\0'};

	if (strchr(spaceset, str) != NULL)
		return 1;

	return 0;
}

int qcsapi_ascii_to_hexstr(const char *str, char *hex, int bufsize)
{
	int i;
	int length;

	length = strlen(str);

	if (bufsize < ((length * 2) + 1))
		return -1;

	for (i = 0; i < length; i++)
		snprintf(hex + i * 2, 3, "%X", str[i]);

	hex[length * 2] = '\0';

	return 0;
}

static int local_hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int local_hex2byte(const char *hex)
{
	int a, b;
	a = local_hex2num(*hex++);
	if (a < 0)
		return -1;
	b = local_hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * qcsapi_util_hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int qcsapi_util_hexstr2bin(const char *hex, unsigned char *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	unsigned char *opos = buf;

	for (i = 0; i < len; i++) {
		a = local_hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

/*
 * Copied from dup_binstr in hostapd-2.1/src/utils/common.c
 */
static
char *qcsqpi_util_dup_binstr(const void *src, size_t len)
{
	char *res;

	if (src == NULL)
		return NULL;
	res = malloc(len + 1);
	if (res == NULL)
		return NULL;
	memcpy(res, src, len);
	res[len] = '\0';

	return res;
}

/*
 * Copied from printf_decode in hostapd-2.1/src/utils/common.c
 */
static
size_t qcsapi_util_printf_decode(uint8_t *buf, size_t maxlen, const char *str)
{
	const char *pos = str;
	size_t len = 0;
	int val;

	while (*pos) {
		if (len + 1 >= maxlen)
			break;
		switch (*pos) {
		case '\\':
			pos++;
			switch (*pos) {
			case '\\':
				buf[len++] = '\\';
				pos++;
				break;
			case '"':
				buf[len++] = '"';
				pos++;
				break;
			case 'n':
				buf[len++] = '\n';
				pos++;
				break;
			case 'r':
				buf[len++] = '\r';
				pos++;
				break;
			case 't':
				buf[len++] = '\t';
				pos++;
				break;
			case 'e':
				buf[len++] = '\e';
				pos++;
				break;
			case 'x':
				pos++;
				val = local_hex2byte(pos);
				if (val < 0) {
					val = local_hex2num(*pos);
					if (val < 0)
						break;
					buf[len++] = val;
					pos++;
				} else {
					buf[len++] = val;
					pos += 2;
				}
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				val = *pos++ - '0';
				if (*pos >= '0' && *pos <= '7')
					val = val * 8 + (*pos++ - '0');
				if (*pos >= '0' && *pos <= '7')
					val = val * 8 + (*pos++ - '0');
				buf[len++] = val;
				break;
			default:
				break;
			}
			break;
		default:
			buf[len++] = *pos++;
			break;
		}
	}
	if (maxlen > len)
		buf[len] = '\0';

	return len;
}

/*
 * Copied from wpa_config_parse_string in hostapd-2.1/src/utils/common.c
 */
char *qcsapi_util_parse_string(const char *value, size_t *len)
{
	if (*value == '"') {
		const char *pos;
		char *str;
		value++;
		pos = strrchr(value, '"');
		if (pos == NULL || pos[1] != '\0')
			return NULL;
		*len = pos - value;
		str = qcsqpi_util_dup_binstr(value, *len);
		if (str == NULL)
			return NULL;
		return str;
	} else if (*value == 'P' && value[1] == '"') {
		const char *pos;
		char *tstr, *str;
		size_t tlen;
		value += 2;
		pos = strrchr(value, '"');
		if (pos == NULL || pos[1] != '\0')
			return NULL;
		tlen = pos - value;
		tstr = qcsqpi_util_dup_binstr(value, tlen);
		if (tstr == NULL)
			return NULL;

		str = malloc(tlen + 1);
		if (str == NULL) {
			free(tstr);
			return NULL;
		}

		*len = qcsapi_util_printf_decode((uint8_t *) str, tlen + 1, tstr);
		free(tstr);

		return str;
	} else {
		uint8_t *str;
		size_t tlen, hlen = strlen(value);
		if (hlen & 1)
			return NULL;
		tlen = hlen / 2;
		str = malloc(tlen + 1);
		if (str == NULL)
			return NULL;
		if (qcsapi_util_hexstr2bin(value, str, tlen)) {
			free(str);
			return NULL;
		}
		str[tlen] = '\0';
		*len = tlen;
		return (char *) str;
	}
}
