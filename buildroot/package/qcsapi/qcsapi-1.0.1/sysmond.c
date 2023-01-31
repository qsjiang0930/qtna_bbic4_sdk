/*SH0
 *******************************************************************************
 **                                                                           **
 **         Copyright (c) 2018 Quantenna Communications, Inc.                 **
 **                                                                           **
 **  File        : sysmond.c                                                  **
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <syslog.h>
#include <net/if.h>
#include <errno.h>
#include "qcsapi.h"
#include "qtn/muc_txrx_stats.h"
#include "ini.h"

#define QSYSMON_VERSION		"1.0"
#define QSYSMON_TAG		"QSYSMON"

#define QSYSMON_DFLT_SP_FAIL_UP_THRSHLD		10000
#define QSYSMON_DFLT_LP_FAIL_UP_THRSHLD		100
#define QSYSMON_DFLT_CCA_IDLE_LO_THRSHLD	400
#define QSYSMON_DFLT_CCA_INTF_UP_THRSHLD	300
#define QSYSMON_DFLT_TX_RETRIES_UP_THRSHLD	15
#define QSYSMON_DFLT_CPU_UTILIZATION_UP_THRSHLD	100
#define QSYSMON_DFLT_FREE_RAM_LO_THRSHLD	2000
#define QSYSMON_DFLT_TX_PKTS_UP_THRSHLD		20

#define QDRVCMD		"qdrvcmd get 0 muc_sreset_stats"
#define QDRVDATA	"/proc/qdrvdata"
#define LOADAVG		"/proc/loadavg"

#define FMT_UINT32_LEN_MAX	10

/*
 * The size of the buffer used to store a string containing MUC_SRESET_STATS_NUM
 * values of type uint32_t, each of which is separated by a single space character,
 * including the trailing zero.
*/
#define SRESET_STATS_LOG_BUFSZ	(MUC_SRESET_STATS_NUM * (FMT_UINT32_LEN_MAX + 1) + 1)

struct qsysmon_counters {
	uint32_t tx_pkts;
	uint32_t tx_retries;
	uint32_t cnt_sp_fail;
	uint32_t cnt_lp_fail;
	uint32_t cpu_utilization;
	uint32_t free_ram;
	uint32_t sreset_begin;
	uint32_t sreset_stats[MUC_SRESET_STATS_NUM];
	uint16_t cca_idle;
	uint16_t cca_busy;
	uint16_t cca_intf;
};

struct qsysmon_config {
	char *conf_file;
	uint32_t cnt_sp_fail_upper_th;
	uint32_t cnt_lp_fail_upper_th;
	uint32_t cpu_utilization_upper_th;
	uint32_t free_ram_lower_th;
	uint16_t cca_idle_lower_th;
	uint16_t cca_intf_upper_th;
	uint16_t tx_retries_upper_th;
	uint16_t tx_pkts_upper_th;
};

static struct qsysmon_config config;
static int debug = 0;

static int qsysmon_ini_handler(void *user, const char *section, const char *name, const char *value)
{
	struct qsysmon_config *cfg = user;
	int v;

	if (strcmp(section, "thresholds")) {
		fprintf(stderr, QSYSMON_TAG ": config error, unsupported section: %s\n", section);
		return 0;
	}

	if (!strcmp(name, "cnt_sp_fail_upper_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" cnt_sp_fail_upper_th < 0\n");
			return 0;
		}
		cfg->cnt_sp_fail_upper_th = v;
	} else if (!strcmp(name, "cnt_lp_fail_upper_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" cnt_lp_fail_upper_th < 0\n");
			return 0;
		}
		cfg->cnt_lp_fail_upper_th = v;
	} else if (!strcmp(name, "cca_idle_lower_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" cca_idle_lower_th < 0\n");
			return 0;
		}
		cfg->cca_idle_lower_th = v;
	} else if (!strcmp(name, "cca_intf_upper_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" cca_inf_upper_th < 0\n");
			return 0;
		}
		cfg->cca_intf_upper_th = v;
	} else if (!strcmp(name, "tx_retries_upper_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" tx_retries_upper_th < 0\n");
			return 0;
		}
		cfg->tx_retries_upper_th = v > 100 ? 100 : v;
	} else if (!strcmp(name, "cpu_utilization_upper_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" cpu_utilization_upper_th < 0\n");
			return 0;
		}
		cfg->cpu_utilization_upper_th = v;
	} else if (!strcmp(name, "free_ram_lower_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" free_ram_lower_th < 0\n");
		}
		cfg->free_ram_lower_th = v;
	} else if (!strcmp(name, "tx_pkts_upper_th")) {
		v = atoi(value);
		if (v < 0) {
			fprintf(stderr, QSYSMON_TAG ": config error, parameter"
				" tx_pkts_upper_th < 0\n");
		}
		cfg->tx_pkts_upper_th = v;
	} else {
		fprintf(stderr, QSYSMON_TAG ": config error, unsupported parameter: %s\n",
			name);
		return 0;
	}

	return 1;
}

static int qsysmon_config_init(struct qsysmon_config *cfg)
{
	int error;

	cfg->cnt_sp_fail_upper_th = QSYSMON_DFLT_SP_FAIL_UP_THRSHLD;
	cfg->cnt_lp_fail_upper_th = QSYSMON_DFLT_LP_FAIL_UP_THRSHLD;
	cfg->cca_idle_lower_th = QSYSMON_DFLT_CCA_IDLE_LO_THRSHLD;
	cfg->cca_intf_upper_th = QSYSMON_DFLT_CCA_INTF_UP_THRSHLD;
	cfg->tx_retries_upper_th = QSYSMON_DFLT_TX_RETRIES_UP_THRSHLD;
	cfg->cpu_utilization_upper_th = QSYSMON_DFLT_CPU_UTILIZATION_UP_THRSHLD;
	cfg->free_ram_lower_th = QSYSMON_DFLT_FREE_RAM_LO_THRSHLD;
	cfg->tx_pkts_upper_th = QSYSMON_DFLT_TX_PKTS_UP_THRSHLD;

	if (cfg->conf_file) {
		error = ini_parse(cfg->conf_file, qsysmon_ini_handler, cfg);
		if (error) {
			fprintf(stderr, QSYSMON_TAG ": ini_parse[%s] %s = %d\n", cfg->conf_file,
				error > 0 ? "parse error, line" : "error code", error);
			return -1;
		}
	}

	if (debug) {
		fprintf(stderr, "cnt_sp_fail_upper_th=%u\n", cfg->cnt_sp_fail_upper_th);
		fprintf(stderr, "cnt_lp_fail_upper_th=%u\n", cfg->cnt_lp_fail_upper_th);
		fprintf(stderr, "cca_idle_lower_th=%u\n", cfg->cca_idle_lower_th);
		fprintf(stderr, "cca_intf_upper_th=%u\n", cfg->cca_intf_upper_th);
		fprintf(stderr, "tx_retries_upper_th=%u\n", cfg->tx_retries_upper_th);
		fprintf(stderr, "cpu_utilization_upper_th=%u\n", cfg->cpu_utilization_upper_th);
		fprintf(stderr, "free_ram_lower_th=%u\n", cfg->free_ram_lower_th);
		fprintf(stderr, "tx_pkts_upper_th=%u\n", cfg->tx_pkts_upper_th);
	}

	return 0;
}

static int qsysmon_get_cpu_utilization(unsigned long *cpu_utilization)
{
	int retval = 0;
	FILE *fp;
	unsigned int load_avg = 0;
	unsigned int load_avg_fraction = 0;

	fp = fopen(LOADAVG, "r");
	if (!fp) {
		fprintf(stderr, QSYSMON_TAG ": fopen(" LOADAVG ") failed,"
			" errno = %d\n", errno);
		return -1;
	}

	if (fscanf(fp, "%u.%u %*u.%*u %*u.%*u %*u/%*u %*u\n", &load_avg, &load_avg_fraction) == 2) {
		*cpu_utilization = load_avg * 100 + load_avg_fraction;
		retval = 0;
	} else {
		fprintf(stderr, QSYSMON_TAG ": fscanf matched less items than expected,"
			" while reading from " LOADAVG "\n");
		*cpu_utilization = 0;
		retval = -1;
	}
	fclose(fp);
	return retval;
}

static int qsysmon_read_counters(const char *ifname, struct qsysmon_counters *c)
{
	int i;
	int retval;
	unsigned long cpu_utilization = 0;
	struct qcsapi_scs_currchan_rpt scs_rpt;
	qcsapi_phy_stats phy_stats;
	struct sysinfo si;
	FILE *fp;

	retval = qcsapi_wifi_get_scs_currchan_report(ifname, &scs_rpt);
	if (retval < 0) {
		fprintf(stderr, QSYSMON_TAG ": get SCS current channel report failed, err code = %d\n", retval);
		return retval;
	}

	retval = qcsapi_get_phy_stats(ifname, &phy_stats);
	if (retval < 0) {
		fprintf(stderr, QSYSMON_TAG ": get PHY stats failed, err code = %d\n", retval);
		return retval;
	}

	retval = system(QDRVCMD);
	if (retval) {
		fprintf(stderr, QSYSMON_TAG ": get MuC sreset stats failed, err code = %d\n", retval);
		return retval;
	}

	fp = fopen(QDRVDATA, "r");
	if (!fp) {
		fprintf(stderr, QSYSMON_TAG ": file (" QDRVDATA ") open failed, errno = %d\n", errno);
		return -errno;
	}

	i = 0;
	while(!feof(fp) && i < ARRAY_SIZE(c->sreset_stats)) {
		if (!fscanf(fp, "%u", &c->sreset_stats[i]))
			break;
		i++;
	}

	fclose(fp);

	if (i != ARRAY_SIZE(c->sreset_stats)) {
		fprintf(stderr, QSYSMON_TAG ": error reading from " QDRVDATA "\n");
		return -1;
	}

	if (sysinfo(&si) < 0) {
		fprintf(stderr, QSYSMON_TAG ": sysinfo failed, errno = %d\n", errno);
		return -errno;
	}

	if (qsysmon_get_cpu_utilization(&cpu_utilization) < 0)
		return -1;

	c->cca_idle = scs_rpt.cca_idle;
	c->cca_intf = scs_rpt.cca_intf;
	c->cca_busy = scs_rpt.cca_busy;
	c->tx_pkts  = phy_stats.tx_pkts;
	c->tx_retries = phy_stats.tx_retries;
	c->cnt_sp_fail = phy_stats.cnt_sp_fail;
	c->cnt_lp_fail = phy_stats.cnt_lp_fail;
	c->cpu_utilization = (uint32_t) cpu_utilization;
	c->free_ram = (uint32_t) (si.freeram / 1024);

	return 0;
}

static void
qsysmon_check_counters(const char *ifname, struct qsysmon_counters *c,
				struct qsysmon_config *cfg)
{
	unsigned ratio;

	if (cfg->cpu_utilization_upper_th && c->cpu_utilization > cfg->cpu_utilization_upper_th) {
		syslog(LOG_WARNING, "CPU utilization threshold was reached,"
			" cpu utilization %u %%, cpu utilization threshold %u %%\n",
			c->cpu_utilization, cfg->cpu_utilization_upper_th);
	}

	if (c->free_ram < cfg->free_ram_lower_th) {
		syslog(LOG_WARNING, "MEM usage exceeded threshold,"
			" free memory %u kByte, free memory threshold %u kByte\n",
			c->free_ram, cfg->free_ram_lower_th);
	}

	if (c->sreset_begin != c->sreset_stats[0]) {
		int i;
		char buf[SRESET_STATS_LOG_BUFSZ];
		char *p = buf;

		for (i = 0; i < ARRAY_SIZE(c->sreset_stats); i++)
			p += sprintf(p, " %u", c->sreset_stats[i]);
		*p = 0;

		syslog(LOG_NOTICE, "SRST%s", buf);

		c->sreset_begin = c->sreset_stats[0];
	}

	if (cfg->cca_idle_lower_th && cfg->cca_intf_upper_th)
		if (c->cca_idle < cfg->cca_idle_lower_th && c->cca_intf > cfg->cca_intf_upper_th) {
			syslog(LOG_NOTICE,
				"INTF tx_pkts %u tx_retries %u cnt_sp_fail %u cnt_lp_fail %u"
				" cca_busy %u cca_intf %u cca_idle %u", c->tx_pkts, c->tx_retries,
				c->cnt_sp_fail, c->cnt_lp_fail, c->cca_busy, c->cca_intf,
				c->cca_idle);
			return;
		}

	if (cfg->cnt_sp_fail_upper_th || cfg->cnt_lp_fail_upper_th)
		if (c->cnt_sp_fail > cfg->cnt_sp_fail_upper_th ||
			c->cnt_lp_fail > cfg->cnt_lp_fail_upper_th) {
			syslog(LOG_NOTICE,
				"INTF tx_pkts %u tx_retries %u cnt_sp_fail %u cnt_lp_fail %u"
				" cca_busy %u cca_intf %u cca_idle %u", c->tx_pkts, c->tx_retries,
				c->cnt_sp_fail, c->cnt_lp_fail, c->cca_busy, c->cca_intf,
				c->cca_idle);
			return;
		}

	if (cfg->tx_retries_upper_th && c->tx_pkts > cfg->tx_pkts_upper_th && c->tx_retries) {
		ratio = (100 * c->tx_retries) / c->tx_pkts;
		if (ratio > cfg->tx_retries_upper_th) {
			syslog(LOG_NOTICE,
				"INTF tx_pkts %u tx_retries %u cnt_sp_fail %u cnt_lp_fail %u"
				" cca_busy %u cca_intf %u cca_idle %u", c->tx_pkts, c->tx_retries,
				c->cnt_sp_fail, c->cnt_lp_fail, c->cca_busy, c->cca_intf,
				c->cca_idle);
			return;
		}
	}
}

static void print_usage()
{
	printf("Usage: sysmond [-h] [-d] [-v] [-c CONF_FILE] [-i INIT_TIMEOUT]"
		" [-t POLL_TIMEOUT]\n");
	printf("\nOptional arguments:\n");
	printf("    -h                 Print this message and exit\n");
	printf("    -v                 Print version and exit\n");
	printf("    -c CONF_FILE       Read configuration parameters from CONF_FILE\n");
	printf("    -i INIT_TIMEOUT    Initialization timeout in seconds (default: 0)\n");
	printf("    -t POLL_TIMEOUT    Polling interval in seconds (default: 1)\n");
	printf("    -d                 Run in debug mode\n");
	printf("\nExit status:\n");
	printf("    0 if OK,\n");
	printf("    1 if any problem (e.g. cannot initialize QCSAPI)\n");
}

int main(int argc, char *argv[])
{
	int i;
	int retval;
	int poll_timeout = 1;
	int init_timeout = 0;
	char ifname[IFNAMSIZ];
	struct qsysmon_counters counters;
	extern char *optarg;

	openlog(QSYSMON_TAG, LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	while ((i = getopt(argc, argv, "dhvc:i:t:")) != -1) {
		switch (i) {
		case 'v':
			printf(QSYSMON_VERSION "\n");
			goto bail;
		case 'c':
			config.conf_file = strdup(optarg);
			if (!config.conf_file)
				goto bail;
			break;
		case 'i':
			init_timeout = atoi(optarg);
			break;
		case 't':
			poll_timeout = atoi(optarg);
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		default:
			print_usage();
			goto bail;
		}
	}

	if (init_timeout < 0 || poll_timeout < 1)
		goto bail;

	syslog(LOG_NOTICE, "system monitor v%s started", QSYSMON_VERSION);

	sleep(init_timeout);

	memset(&counters, 0, sizeof(struct qsysmon_counters));

	if (qsysmon_config_init(&config))
		goto bail;

	if (qcsapi_init() < 0) {
		fprintf(stderr, QSYSMON_TAG ": could not initialize QCSAPI\n");
		goto bail;
	}

	if (!debug)
		qcsapi_console_disconnect();

	retval = qcsapi_get_primary_interface(ifname, sizeof(ifname));
	if (retval < 0) {
		fprintf(stderr, QSYSMON_TAG ": could not get primary interface\n");
		goto bail;
	}

	while (1) {
		retval = qsysmon_read_counters(ifname, &counters);
		if (retval >= 0)
			qsysmon_check_counters(ifname, &counters, &config);
		sleep(poll_timeout);
	}

bail:
	closelog();

	return EXIT_FAILURE;
}
