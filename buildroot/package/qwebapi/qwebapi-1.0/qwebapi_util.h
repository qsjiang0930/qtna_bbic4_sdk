/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.                 **
**                                                                           **
**  File        : qwebapi_util.h                                             **
**  Description :                                                            **
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

#ifndef _QWEBAPI_UTIL_H_
#define _QWEBAPI_UTIL_H_

#include <unistd.h>
#include <net/if.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#endif

#include <qtn/qtn_vlan.h>
#include <qcsapi.h>
#include "qwebapi_core.h"

#define ARR_START                               (".{")
#define ARR_END                                 ("}")
#define QWEB_WIRELESS_CONF_FILE_PATH            ("/mnt/jffs2/wireless_conf.txt")
#define QWEBAPI_DELIM_AND                       ("&")
#define QWEBAPI_DELIM_EQUAL                     ("=")
#define QWEBAPI_MAC_ADDR_STR_LEN                (17)
#define QWEB_TMP_CFG_DIR			"/tmp/.qwebcfg/"

void safe_free(void *ptr);
int qweb_get_key_index(char *path, char *key);
void qweb_dump_mac_addr(qcsapi_mac_addr mac_addr, char *value);
int qweb_get_ip_addr(char *ip_addr);
char *string_trim(char *buf);
int qweb_set_inactive_cfg(const char *path, const char *value);
int qweb_get_inactive_cfg(const char *path, char *buf, int len);
void qweb_clean_inactive_cfg();
int qweb_get_bss_count(JSON *json_cfg);
#endif
