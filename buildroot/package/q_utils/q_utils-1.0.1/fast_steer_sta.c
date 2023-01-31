/*
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : fast_steer_sta.c                                           **
**  Description : command line tool to steer station using BSS Transition    **
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
*/

#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <dirent.h>
#include <endian.h>
#include <byteswap.h>
#include <syslog.h>
#include <linux/types.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_qrpe.h>
#include <wireless.h>

#define MAC_LEN 6
#define COPYMAC(dst, src) \
	do {\
		memcpy((dst), (src), MAC_LEN);\
	} while (0)
#define ISZEROMAC(addr) (!(memcmp((addr), zeromac, MAC_LEN)))
#define MACFMT "02x:%02x:%02x:%02x:%02x:%02x"
#define MACARG(sta) (sta)[0],(sta)[1],(sta)[2],(sta)[3],(sta)[4],(sta)[5]
#define BIT(value) (1<<((value)))
#define IEEE80211_TRANSREQ_CANDIDATE_INCLUDED_SHIFT  (0)
#define IEEE80211_TRANSREQ_ABRIDGED_SHIFT            (1)
#define IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT        (2)
#define IEEE80211_TRANSREQ_BSS_TERM_SHIFT            (3)
#define IEEE80211_TRANSREQ_ESS_DISASSOC_SHIFT        (4)
/* BSSID Information field */
#define IEEE80211_BSSIDINFO_REACHABILITY_SHIFT	(0)
#define IEEE80211_BSSIDINFO_SECURITY_SHIFT		(2)
#define IEEE80211_BSSIDINFO_KEY_SCOPE_SHIFT		(3)
#define IEEE80211_BSSIDINFO_SPECTRUM_SHIFT		(4)
#define IEEE80211_BSSIDINFO_QOS_SHIFT		(5)
#define IEEE80211_BSSIDINFO_APSD_SHIFT		(6)
#define IEEE80211_BSSIDINFO_RADIO_MEAS_SHIFT		(7)
#define IEEE80211_BSSIDINFO_DELAYED_BA_SHIFT		(8)
#define IEEE80211_BSSIDINFO_IMM_BA_SHIFT		(9)
#define IEEE80211_BSSIDINFO_MOBILITY_SHIFT		(10)
#define IEEE80211_BSSIDINFO_HT_SHIFT			(11)
#define IEEE80211_BSSIDINFO_VHT_SHIFT		(12)


#define DEFAULT_BSS_TRANSMODE \
	(BIT(IEEE80211_TRANSREQ_CANDIDATE_INCLUDED_SHIFT)\
	 | BIT(IEEE80211_TRANSREQ_ABRIDGED_SHIFT)\
	| BIT(IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT))

typedef struct {
	char *intf;
	struct ieee80211_qrpe_intf_info intf_info;
	struct ether_addr client;
	struct ether_addr dst_bss;
	int dst_channel;
	int disassoc_timer;
	int val_intvl;
	int ioctl_sock;
} bss_trans_ctrl_t;

static bss_trans_ctrl_t bsstrans = { 0 };
static char zeromac[MAC_LEN] = { 0 };

static int debug = 0;

void print_help()
{
	printf
	    ("Usage:\n\tfast_steer_sta -n CHANNEL [-d] -i INTERFACE -c CLIENT_MAC -t TARGET_BSS\n");
}

static void parse_args(int argc, char *argv[])
{
	int c;

	bsstrans.disassoc_timer = 1;
	bsstrans.val_intvl = 10;
	while ((c = getopt(argc, argv, "c:t:n:r:v:i:dh")) != -1) {
		switch (c) {
		case 'c':
			ether_aton_r(optarg, &bsstrans.client);

			break;
		case 't':
			ether_aton_r(optarg, &bsstrans.dst_bss);
			break;
		case 'n':
			bsstrans.dst_channel = atoi(optarg);
			break;
		case 'r':
			bsstrans.disassoc_timer = atoi(optarg);
			break;
		case 'v':
			bsstrans.val_intvl = atoi(optarg);
			break;
		case 'i':
			bsstrans.intf = strdup(optarg);
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			print_help();
			break;
		default:
			break;
		}
	}
}

static int open_ctrl_sock()
{
	if (((bsstrans.ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0))) <= 0)
		return -1;
	return 0;
}

static int sub_ioctl_command(int skfd, const char *ifname,
				   int16_t sub_cmd, void *param,
				   uint16_t len)
{
	struct iwreq wrq;
	int ret = 0;

	if (skfd < 0) {
		return -EINVAL;
	}

	if (strlen(ifname) >= sizeof(wrq.ifr_name))
		return -EINVAL;
	strcpy(wrq.ifr_name, ifname);

	wrq.u.data.flags = sub_cmd;
	wrq.u.data.pointer = param;
	wrq.u.data.length = len;

	ret = ioctl(skfd, IEEE80211_IOCTL_EXT, &wrq);

	return ret;
}

static int get_intf_info()
{
	int ret;

	ret =
	    sub_ioctl_command(bsstrans.ioctl_sock, bsstrans.intf,
				    SIOCDEV_SUBIO_GET_BSA_INTF_INFO,
				    &bsstrans.intf_info,
				    sizeof(struct
					   ieee80211_qrpe_intf_info));
	if (debug)
		printf("get intf result = %d\n", ret);

	return ret;
}

static uint32_t build_bssinfo()
{
	uint32_t info = BIT(IEEE80211_BSSIDINFO_MOBILITY_SHIFT);

	uint8_t cap = bsstrans.intf_info.capinfo >> 8;


	if (cap & (BIT(0)))
		info |= (BIT(IEEE80211_BSSIDINFO_SPECTRUM_SHIFT));

	if (cap & (BIT(1)))
		info |= (BIT(IEEE80211_BSSIDINFO_QOS_SHIFT));

	if (cap & (BIT(3)))
		info |= (BIT(IEEE80211_BSSIDINFO_APSD_SHIFT));

	if (cap & (BIT(4)))
		info |= (BIT(IEEE80211_BSSIDINFO_RADIO_MEAS_SHIFT));

	if (cap & (BIT(6)))
		info |= (BIT(IEEE80211_BSSIDINFO_DELAYED_BA_SHIFT));

	if (cap & (BIT(7)))
		info |= (BIT(IEEE80211_BSSIDINFO_IMM_BA_SHIFT));


	return info;
}

static int do_bss_trans()
{
	struct ieee80211_qrpe_btm_req qrpe_btm_req_frm;
	int ret;

	COPYMAC(qrpe_btm_req_frm.mac,
		bsstrans.client.ether_addr_octet);

	qrpe_btm_req_frm.disassoc_timer = bsstrans.disassoc_timer;
	qrpe_btm_req_frm.req_mode = DEFAULT_BSS_TRANSMODE;
	qrpe_btm_req_frm.val_intvl = bsstrans.val_intvl;

	COPYMAC(qrpe_btm_req_frm.bssid, bsstrans.dst_bss.ether_addr_octet);

	qrpe_btm_req_frm.bssid_info = build_bssinfo();

	qrpe_btm_req_frm.opclass = bsstrans.intf_info.opclass;
	if (debug)
		printf("opclass = %d\n", qrpe_btm_req_frm.opclass);

	qrpe_btm_req_frm.channel = bsstrans.dst_channel;
	if (debug)
		printf("dst channel = %d\n", qrpe_btm_req_frm.channel);

	qrpe_btm_req_frm.phytype = bsstrans.intf_info.phytype;
	if (debug)
		printf("phytype = %d\n", qrpe_btm_req_frm.phytype);
	qrpe_btm_req_frm.subel_len = 0;

	ret =
	    sub_ioctl_command(bsstrans.ioctl_sock, bsstrans.intf,
				    SIOCDEV_SUBIO_SEND_BTM_REQ_FRM,
				    &qrpe_btm_req_frm,
				    sizeof(struct
					   ieee80211_qrpe_btm_req));
	if (debug)
		printf("bss trans result = %d\n", ret);
	return ret;
}


int main(int argc, char *argv[])
{
	int ret = -1;

	bsstrans.ioctl_sock = -1;

	parse_args(argc, argv);

	if ((bsstrans.intf == NULL)
	    || (ISZEROMAC(bsstrans.dst_bss.ether_addr_octet))
	    || (ISZEROMAC(bsstrans.client.ether_addr_octet))
	    || (bsstrans.dst_channel == 0) || (bsstrans.disassoc_timer == 0) || (bsstrans.val_intvl == 0))
		goto bail;

	if (debug)
		printf("try move %" MACFMT " to BSS %" MACFMT
		       "(channel %d) from %s\n",
		       MACARG(bsstrans.client.ether_addr_octet),
		       MACARG(bsstrans.dst_bss.ether_addr_octet),
		       bsstrans.dst_channel, bsstrans.intf);

	if ((ret = open_ctrl_sock()))
		goto bail;

	if ((ret = get_intf_info()))
		goto bail;

	if ((ret = do_bss_trans()))
		goto bail;

	ret = 0;
bail:
	if (bsstrans.intf)
		free(bsstrans.intf);
	if (bsstrans.ioctl_sock >= 0)
		close(bsstrans.ioctl_sock);

	return ret;
}
