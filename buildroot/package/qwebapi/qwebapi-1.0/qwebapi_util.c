/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2015 Quantenna Communications, Inc.                 **
**                                                                           **
**  File        : qwebapi_util.c                                             **
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

#define _GNU_SOURCE
#include <fcntl.h>
#include <dirent.h>
#include "qwebapi.h"
#include "qwebapi_util.h"

static int qweb_defer_mode = 0;
static int qweb_inactive_mode = 0;

void safe_free(void *ptr)
{
	if (ptr)
		free(ptr);
}

int qweb_get_key_index(char *path, char *key)
{
	char *start;
	int index = 0;
	char needle[32 + 1];

	assert(path != NULL && key != NULL);

	strncpy(needle, key, 32);
	strcat(needle, ARR_START);

	start = strcasestr(path, (char *)needle);
	if (start) {
		index = atoi(start + strlen(needle));
	}

	return (index > 0) ? index : 0;
}

void qweb_dump_mac_addr(qcsapi_mac_addr mac_addr, char *value)
{

	snprintf(value, QWEBAPI_MAC_ADDR_STR_LEN + 1,
		 "%02X:%02X:%02X:%02X:%02X:%02X",
		 mac_addr[0], mac_addr[1], mac_addr[2],
		 mac_addr[3], mac_addr[4], mac_addr[5]);
}

int qweb_get_ip_addr(char *ip_addr)
{
	int sock_get_ip;
	struct sockaddr_in *sin;
	struct ifreq ifr_ip;

	if ((sock_get_ip = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return -1;

	memset(&ifr_ip, 0, sizeof(ifr_ip));
	strncpy(ifr_ip.ifr_name, "eth1_0", sizeof(ifr_ip.ifr_name) - 1);

	if (ioctl(sock_get_ip, SIOCGIFADDR, &ifr_ip) < 0) {
		strncpy(ifr_ip.ifr_name, "br0", sizeof(ifr_ip.ifr_name) - 1);
		if (ioctl(sock_get_ip, SIOCGIFADDR, &ifr_ip) < 0) {
			close(sock_get_ip);
			return -1;
		}
	}
	sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
	strncpy(ip_addr, (char *)inet_ntoa(sin->sin_addr), 16);

	close(sock_get_ip);

	return 0;
}

char *string_trim(char *buf)
{
	int i;

	while (*buf && isspace(*buf)) {
		buf++;
	}

	for (i = strlen(buf) - 1; isspace(buf[i]); i--) {
		buf[i] = '\0';
	}

	return buf;
}
void qweb_set_defer_mode(int enable)
{
	qweb_defer_mode = (enable == 1);
}

int qweb_get_defer_mode(void)
{
	return (qweb_defer_mode == 1);
}

void qweb_set_inactive_mode(int enable)
{
	qweb_inactive_mode = (enable == 1);
}

int qweb_get_inactive_mode(void)
{
	return (qweb_inactive_mode == 1);
}

int qweb_set_inactive_cfg(const char *path, const char *value)
{
	FILE *fp;
	char *filename;

	filename = malloc(strlen(QWEB_TMP_CFG_DIR) + strlen(path) + 1);
	if (!filename) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, fail to alloc memory\n",
			   __func__, __LINE__);
		return -1;
	}

	sprintf(filename, "%s%s", QWEB_TMP_CFG_DIR, path);
	fp = fopen(filename, "w");
	if (!fp) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, create directory %s\n",
			   __func__, __LINE__, QWEB_TMP_CFG_DIR);

		if (mkdir(QWEB_TMP_CFG_DIR, S_IRWXU) != 0) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, cannot create directory %s\n",
				   __func__, __LINE__, QWEB_TMP_CFG_DIR);
			free(filename);
			return -1;
		}
		fp = fopen(filename, "w");
		if (!fp) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, cannot open %s for write\n",
				   __func__, __LINE__, filename);
			free(filename);
			return -1;
		}
	}

	fputs(value, fp);
	fclose(fp);
	free(filename);

	return 0;
}

int qweb_get_inactive_cfg(const char *path, char *buf, int len)
{
	FILE *fp;
	char *filename;
	int ret = 0;

	filename = malloc(strlen(QWEB_TMP_CFG_DIR) + strlen(path) + 1);
	if (!filename) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, fail to alloc memory\n",
			   __func__, __LINE__);
		return -1;
	}

	sprintf(filename, "%s%s", QWEB_TMP_CFG_DIR, path);
	fp = fopen(filename, "r");
	if (!fp) {
		free(filename);
		return -1;
	}

	if (fgets(buf, len, fp) == NULL)
		ret = -1;

	fclose(fp);
	free(filename);

	return ret;
}

void qweb_clean_inactive_cfg()
{
	struct dirent *dent;
	DIR *dir;

	dir = opendir(QWEB_TMP_CFG_DIR);
	if (dir == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, cannot open directory %s\n",
			   __func__, __LINE__, QWEB_TMP_CFG_DIR);
		return;
	}

	if (0 != chdir(QWEB_TMP_CFG_DIR)) {
		closedir(dir);
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, cannot change directory %s\n",
			   __func__, __LINE__, QWEB_TMP_CFG_DIR);
		return;
	}
	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		unlink(dent->d_name);
	}
	if (0 != closedir(dir))
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, cannot close directory\n",
			   __func__, __LINE__);

	if (0 != chdir("/")) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, cannot change directory root\n",
			   __func__, __LINE__);
		return;
	}

	if (0 != rmdir(QWEB_TMP_CFG_DIR))
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, cannot remove directory %s\n",
			   __func__, __LINE__, QWEB_TMP_CFG_DIR);
}

int qweb_get_bss_count(JSON *json_cfg)
{
#define MAX_NUM_BSS_SUPP 13
	int cnt = 0;
	JSON *ssid_array;

	JSON_GET_OBJ(json_cfg, "SSID", &ssid_array);
	while (cnt <= MAX_NUM_BSS_SUPP
		&& JSON_GET_ITEM(ssid_array, cnt))
		cnt++;
	return cnt;
}
