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

#include <stdint.h>
#include <qcsapi.h>

#ifndef max
#define max(a, b) ((a) < (b) ? (b) : (a))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#define MAC_ADDR_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_ARG(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int qcsapi_verify_numeric(const char *parameter_value);
int qcsapi_util_str_to_uint32(const char *str, uint32_t *result);
int qcsapi_util_str_to_int32(const char *str, int32_t *result);
int qcsapi_list_to_array32(const char *input_list, uint32_t *output_array,
		const uint32_t max_count, uint32_t *count);
int parse_mac_addr(const char *mac_addr_as_str, qcsapi_mac_addr mac_addr);
int validate_mac_addr(const char *mac_addr_as_str);
int qcsapi_isspace(char str);
int qcsapi_ascii_to_hexstr(const char *str, char *hex, int bufsize);
char *qcsapi_util_parse_string(const char *value, size_t *len);
int qcsapi_util_hexstr2bin(const char *hex, unsigned char *buf, size_t len);

#ifdef __COVERITY__
#undef isupper
#undef islower
#undef isalpha
#undef isdigit
#undef isxdigit
#undef isspace
#undef ispunct
#undef isalnum
#undef isgraph
#undef isprint
#undef iscntrl
#undef toupper
#undef tolower
#endif
