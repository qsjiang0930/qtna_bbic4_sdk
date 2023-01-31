/**
 * Copyright (c) 2014 Quantenna Communications, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/
#include "qevt_mlpm.h"

static char fpath[QEVT_MAX_LOG_FILE_LEN] = QEVT_DEF_LOG_DIR;
static const char * logname = QEVT_DEF_LOG_FILE;

static char fpath1[QEVT_MAX_LOG_FILE_LEN] = QEVT_DEF_LOG_DIR;
static const char * log1name = QEVT_DEF_BAK_LOG_FILE;

static int log_size = QEVT_DEF_LOG_SIZE;
static char * log_buf = NULL;

static int qevt_write_log(int * fd, void * buf, int len)
{
	off_t file_off;
	int bak_fd;
	int log_bytes;
	int log_fd = *fd;

	if (log_fd >= 0) {
		close(log_fd);
		*fd = -1;
	}

	log_fd = open(fpath, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
	if (log_fd < 0) {
		perror("fail to open file");
		return log_fd;
	}

	file_off = lseek(log_fd, 0, SEEK_END);

	if ((int)file_off + len > log_size) {
		file_off = lseek(log_fd, 0, SEEK_SET);

		log_bytes = read(log_fd, log_buf, log_size);
		if (log_bytes < 0 ) {
			perror("faile to read file");
			close(log_fd);
			*fd = -1;
			return log_bytes;
		}
		close(log_fd);
		*fd = -1;

		bak_fd = open(fpath1, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
		if (bak_fd >= 0) {
			if (log_bytes != write(bak_fd, log_buf, log_bytes)) {
				perror ("fail to write file");
			}
			close(bak_fd);
		} else
			perror("fail to open backup file.");

		log_fd = open(fpath, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
		if (log_fd < 0) {
			perror("fail to open after change log");
			return log_fd;
		}
	}

	log_bytes = write(log_fd, buf, len);
	*fd = log_fd;

	return log_bytes;
}

static int qevt_send_host(struct qevt_client_config *const cfg, const char *msg)
{
	int sent_bytes = 0;
	int ret;

	do {
		ret = send(cfg->client_socket, msg + sent_bytes, strlen(msg) - sent_bytes, 0);
		if (ret > 0) {
			sent_bytes += ret;
		} else if (errno == EINTR) {
			continue;
		} else {
			break;
		}
	} while (sent_bytes < strlen(msg));

	if (ret <= 0) {
		perror("fail to send");
	}
	return (ret > 0);
}

static int qevt_receive(struct qevt_client_config *const cfg)
{
	int received_bytes;

	do {
		received_bytes = recv(cfg->client_socket, cfg->rxbuffer, sizeof(cfg->rxbuffer) - 1, 0);
		if (received_bytes > 0) {
			cfg->rxbuffer[received_bytes] = '\0';
		} else if (received_bytes == 0) {
			printf("Connection closed\n");
			break;
		} else if (errno != EINTR && errno != ECONNREFUSED) {
			perror("Receive failed");
			break;
		}
	} while ((received_bytes < 0) && (errno == EINTR));

	return received_bytes;
}

static char * qevt_config_cmd(struct qevt_client_config *const cfg, const int config_type)
{
	char *msg;
	char *nl;

	/* first, clear to initial settings */
	if (!qevt_send_host(cfg, QEVT_CONFIG_RESET"\n")) {
		return NULL;
	}
	if (qevt_receive(cfg) <= 0) {
		return NULL;
	}

	/* then send config command */
	if (!qevt_send_host(cfg, cfg->qevt_config_cmd)) {
		return NULL;
	}
	if (qevt_receive(cfg) <= 0) {
		return NULL;
	}

	msg = strstr(cfg->rxbuffer, (config_type != ENABLE_CONFIG_CMD) ?
			QEVT_CONFIG_EVENT_ID" " : QEVT_CONFIG" ");
	if (msg) {
		msg = strstr(msg, " ");
	}
	if (msg && (nl = strstr(++msg, "\n"))) {
		*nl = 0;
	}

	return msg;
}

static int qevt_check_version(struct qevt_client_config *const cfg, char** report, const int config_type)
{
	char *version;
	char *nl;
	const char *cmd = QEVT_VERSION" "QEVT_CLIENT_VERSION;

	if (report) {
		*report = "UNKNOWN";
	}

	if (!qevt_send_host(cfg, cmd) || (qevt_receive(cfg) < 0)) {
		return 0;
	}

	version = strstr(cfg->rxbuffer, QEVT_VERSION);
	if (!version) {
		perror("version missing");
		return 0;
	}

	version += strlen(QEVT_VERSION);
	version = strstr(version, "v");
	if (!version) {
		perror("NULL version");
		return 0;
	}

	nl = strstr(version, "\n");
	if (nl) {
		*nl = 0;
	}

	if (report) {
		*report = version;
	}

	if ((strcmp(version, QEVT_CLIENT_VERSION) < 0) &&
			config_type == ENABLE_CONFIG_EVENT_ID) {
		printf("qevt_server[version %s] does not support -e option\n", version);
		return 0;
	}

	return (strcmp(QEVT_CLIENT_VERSION, version) >= 0);
}

static QEVT_RET_E qevt_parsing_cac_msg(char *buffer, struct qevt_client_config *const cfg)
{
	char *found_ptr = NULL;
	int clear_channel = 0;
	char write_buffer[CMD_BUFFER_LEN_MAX] = {0};
	QEVT_RET_E ret = QEVT_PARSING_FAIL;

	if (!buffer)
		return ret;

	found_ptr = strstr(buffer, RADAR_PROMT);
	if (!found_ptr)
		return ret;

	found_ptr = strstr(buffer, CAC_DONE_PROMT);
	if (!found_ptr)
		return ret;

	if (sscanf(found_ptr, CAC_DONE_PROMT" %d", &clear_channel) < 0)
		return ret;

	sprintf(write_buffer, CAC_PROMT" %d\n", clear_channel);
	if (qevt_write_log(&(cfg->fd), write_buffer, strlen(write_buffer)) != strlen(write_buffer))
		return QEVT_GENERAL_FAIL;

	return QEVT_PARSING_SUCCESS;
}

static QEVT_RET_E qevt_parsing_radar_msg(char *buffer)
{
	char *found_ptr = NULL;
	char cmd[CMD_BUFFER_LEN_MAX];
	int radar_channel;
	QEVT_RET_E ret = QEVT_PARSING_FAIL;

	if (!buffer)
		return ret;

	found_ptr = strstr(buffer, RADAR_PROMT);
	if (!found_ptr)
		return ret;

	do {
		found_ptr = strstr(found_ptr, RADAR_DETECTED);
		if (!found_ptr)
			break;

		if (sscanf(found_ptr, RADAR_DETECTED" %d", &radar_channel) < 0)
			break;

		/* delete channel in list */
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd) - 1, "sed -i '/\\<%d\\>/d' %s", radar_channel, fpath);
		system(cmd);
		found_ptr += strlen(RADAR_DETECTED);
		ret = QEVT_PARSING_SUCCESS;
	} while(1);

	return ret;
}

static void qevt_receiving_loop(struct qevt_client_config *const cfg)
{
	int received_bytes;
	char *buffer = cfg->rxbuffer;
	QEVT_RET_E ret;

	for (;;) {
		received_bytes = qevt_receive(cfg);
		if (received_bytes <= 0) {
			break;
		}

		ret = qevt_parsing_cac_msg(buffer, cfg);
		if (ret != QEVT_PARSING_SUCCESS) {
			(void) qevt_parsing_radar_msg(buffer);
		}
	}
}

static int qevt_client_init(struct qevt_client_config *const cfg)
{
	if (cfg->client_socket >= 0)
		close(cfg->client_socket);

	cfg->client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (cfg->client_socket < 0) {
		perror("Failed to create client socket");
		return -1;
	}

	memset(&cfg->dest, 0, sizeof(cfg->dest));
	cfg->dest.sin_family = AF_INET;
	cfg->dest.sin_port = htons(cfg->port);
	cfg->dest.sin_addr = cfg->ip_addr;
	return 0;
}

static int qevt_connected_to_server(const struct qevt_client_config *const cfg)
{
	fd_set fdset;
	struct timeval timeout = {.tv_sec = QEVT_CON_RETRY_DELAY, .tv_usec = 0};
	int connected = 0;

	FD_ZERO(&fdset);
	FD_SET(cfg->client_socket, &fdset);

	if (select(cfg->client_socket + 1, NULL, &fdset, NULL, &timeout) == 1) {
		int so_error;
		socklen_t so_len = sizeof(so_error);

		getsockopt(cfg->client_socket, SOL_SOCKET, SO_ERROR, &so_error, &so_len);
		if (!so_error) {
			connected = 1;
		}
	}

	return connected;
}

static void qevt_client_connect(struct qevt_client_config *const cfg)
{
	int ret;
	int connected = 0;

	while (!connected) {
		ret = fcntl(cfg->client_socket, F_SETFL, O_NONBLOCK);
		if (ret < 0)
			perror("mlpm: failed to set O_NONBLOCK flag");

		ret = connect(cfg->client_socket, (struct sockaddr *)&cfg->dest,
				sizeof(struct sockaddr));

		if (ret < 0) {
			switch (errno) {
			case EINPROGRESS:
				connected = qevt_connected_to_server(cfg);
				if (connected)
					break;
				if (qevt_client_init(cfg) < 0) {
					fprintf(stderr, "fail to create client\n");
				}
				/* Fall through */
			case ECONNREFUSED:
			case ETIMEDOUT:
				fprintf(stderr,
					"Cannot connect to the server. Trying again in %u secs.\n",
						QEVT_CON_RETRY_DELAY);
				sleep(QEVT_CON_RETRY_DELAY);
				break;
			case EINTR:
				break;
			default:
				perror("Cannot connect");
			}
		}
	}

	ret = fcntl(cfg->client_socket, F_GETFL, 0);
	if (ret >= 0) {
		ret = fcntl(cfg->client_socket, F_SETFL, ret & ~O_NONBLOCK);
		if (ret < 0)
			perror("mlpm: failed to clear O_NONBLOCK flag");
	} else
		perror("mlpm: failed to get the flag");

	printf("Connection established\n");
}

static void qevt_usage(char *argv[])
{
	printf("Usage: %s [option]\n"
			"\t-h <host ip addr>\n"
			"\t-p <host ip port>\n"
			"\t-k <file size, unit k>\n", argv[0]);
}

int main(int argc, char *argv[])
{
	static struct qevt_client_config client_cfg;
	uint8_t config_type = 0;
	int ch;
	int status = EXIT_FAILURE;
	char ip_addr[QEVT_MAX_IPADDR_LEN] = "127.0.0.1";

	memset(&client_cfg ,0 ,sizeof(struct qevt_client_config));
	client_cfg.port = QEVT_DEFAULT_PORT;
	if (!inet_aton(ip_addr, &client_cfg.ip_addr)) {
		fprintf(stderr, "Default IP address used is not valid\n");
		goto exit;
	}

	while ((ch = getopt(argc, argv, "h:p:k::")) != -1) {
		switch (ch) {
		case 'h':
			strncpy(ip_addr, optarg, sizeof(ip_addr));
			ip_addr[sizeof(ip_addr) -1] = '\0';
			if (!strncmp("255.255.255.255", ip_addr, strlen(ip_addr))) {
				fprintf(stderr, "please select a valid ip address\n");
				goto exit;
			}
			if (!inet_aton(ip_addr, &client_cfg.ip_addr)) {
				fprintf(stderr, "IP address specified is not valid\n");
				goto exit;
			}
			break;
		case 'p':
			client_cfg.port = atoi(optarg);
			break;
		case 'k':
			if (atoi(optarg) <= QEVT_MAX_LOG_SIZE) {
				log_size = atoi(optarg) * 1024;
			} else {
				fprintf(stderr, "Log size cannot be larger than %d\n",
					QEVT_MAX_LOG_SIZE);
				goto exit;
			}
			break;
		default:
			qevt_usage(argv);
			goto exit;
		}
	}

	if (!client_cfg.qevt_config_cmd) {
		config_type = ENABLE_CONFIG_CMD;
		client_cfg.qevt_config_cmd = malloc(sizeof(QEVT_DEFAULT_CONFIG));
	}

	if (client_cfg.qevt_config_cmd) {
		sprintf(client_cfg.qevt_config_cmd, "%s", QEVT_DEFAULT_CONFIG);
	} else {
		fprintf(stderr, "fail to malloc memory %u bytes\n",
				(unsigned int)(sizeof(QEVT_DEFAULT_CONFIG)));
		goto exit;
	}

	strncat(fpath, "/", 1);
	strncat(fpath, logname, sizeof(fpath) - strlen(fpath) - 1);
	strncat(fpath1, "/", 1);
	strncat(fpath1, log1name, sizeof(fpath1) - strlen(fpath1) - 1);

	client_cfg.client_socket = -1;

	if (qevt_client_init(&client_cfg) < 0) {
		goto exit;
	}

	log_buf = malloc(log_size);

	if(log_buf == NULL) {
		fprintf(stderr, "fail to malloc memory %d bytes\n", log_size);
		goto exit;
	}

	for (;;) {
		char *report = NULL;
		/* coverity[negative_returns] - client_socket cannot be -1 */
		qevt_client_connect(&client_cfg);

		/* coverity[negative_returns] - client_socket cannot be -1 */
		if (!qevt_check_version(&client_cfg, &report, config_type)) {
			fprintf(stderr, "incompatible client version '"QEVT_CLIENT_VERSION
				"'/server version '%s'\n", report);
			goto exit;
		}

		if ((report = qevt_config_cmd(&client_cfg, config_type))) {
			printf("Server configuration '%s'\n", report);
		} else {
			fprintf(stderr, "unable to set/get config\n");
			goto exit;
		}

		qevt_receiving_loop(&client_cfg);
		if (qevt_client_init(&client_cfg) < 0)
			goto exit;
	}
	/*
	 * This point is only reached if the above loop exits (which it should not currently).
	 * In case clean exit is added in future, exit with success status.
	 */
	status = EXIT_SUCCESS;
exit:
	if (log_buf)
		free(log_buf);

	if (client_cfg.qevt_config_cmd)
		free(client_cfg.qevt_config_cmd);

	if (client_cfg.client_socket >= 0)
		close(client_cfg.client_socket);

	if (client_cfg.fd)
		close(client_cfg.fd);

	return status;
}
