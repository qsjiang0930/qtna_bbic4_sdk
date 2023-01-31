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

#include <stdio.h>
#include <getopt.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sysexits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <rpc/clnt.h>
#include <syslog.h>

#include <qcsapi_rpc/client/qcsapi_rpc_client.h>
#include <qcsapi_rpc/generated/qcsapi_rpc.h>
#include <qcsapi_rpc_api.h>

#include "qtn_cmd_parser.h"
#include "qtn_cmd_modules.h"
#include "qtn_log.h"
#include "qtn_common.h"
#include "qtn_ca_config.h"

#define QTN_CA_BACKLOG			5


static int qtn_run_agent();
static void qtn_run_listener(int cmd_pipe_w, int resp_pipe_r);
static void qtn_run_cmdproc(int cmd_pipe_r, int resp_pipe_w);
static void qtn_handle_signal(int signum, siginfo_t *siginfo, void *context);


static volatile int g_qtn_processing = 1;


static
void print_usage(const char *program)
{
	fprintf(stderr, "\nUsage: %s [OPTIONS]\n"
		"  -a [ipaddr|iface]                             the address to bind\n"
		"  -p port                                       the port to bind\n"
		"  -d [raw,iface,mac | tcp,ipaddr | udp,ipaddr]  DUT protocol and address\n"
		"  -b                                            run in background\n"
		"  -c config_name                                name of hostapd configuration\n"
		"  -i icons_folder                               helper icons folder\n",
		program);
}


static
int process_options(int argc, char **argv, int *daemonize)
{
	int c;
	while ((c = getopt(argc, argv, "a:p:d:s:c:i:bh")) != -1)
		switch (c) {
		case 'a':
			if (qtn_config_set_listener_options(optarg, NULL) != 0) {
				fprintf(stderr, "error: invalid address: %s\n", optarg);
				return 1;
			}
			break;

		case 'p':
			if (qtn_config_set_listener_options(NULL, optarg) != 0) {
				fprintf(stderr, "error: invalid port: %s\n", optarg);
				return 1;
			}
			break;

		case 'd':
			if (qtn_config_set_dut_options(optarg) != 0) {
				fprintf(stderr, "error: invalid DUT parameters: %s\n", optarg);
				return 1;
			}
			break;

		case 'c':
			if (qtn_config_set_option("conf_name", optarg) != 0) {
				fprintf(stderr, "error: invalid configuration name: %s\n", optarg);
				return 1;
			}
			break;

		case 'i':
			if (qtn_config_set_option("icons_folder", optarg) != 0) {
				fprintf(stderr, "error: invalid helper icons folder: %s\n", optarg);
				return 1;
			}
			break;

		case 'b':
			*daemonize += 1;
			break;

		case '?':
			if ((optopt == 'a') || (optopt == 'p') || (optopt == 'd')
					|| (optopt == 'c') || (optopt == 'i'))
				fprintf(stderr, "error: option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "error: unknown option -%c.\n", optopt);
			else
				fprintf(stderr, "error: unknown option character \\x%x.\n", optopt);

			return 1;

		case 'h':
		default:
			return 1;
		}

	qtn_config_print();

	if (qtn_config_check() < 0)
		return 1;

	/* configuration looks OK */
	return 0;
}


int main(int argc, char **argv)
{
	int retcode;
	int daemonize = 0;

	qtn_config_init();

	retcode = process_options(argc, argv, &daemonize);

	if (retcode != 0) {
		print_usage(argv[0]);
		goto cleanup;
	}

	if (daemonize && (-1 == daemon(1, 0))) {
		fprintf(stderr, "error: daemon failed (%d)\n", errno);
		retcode = EX_OSERR;
		goto cleanup;
	}

	openlog("qtn_sigma", LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

	retcode = qtn_run_agent();

cleanup:
	qtn_config_cleanup();
	return retcode;
}


static
int qtn_run_agent()
{
	struct sigaction sigact;
	int cmd_pipe[2];
	int resp_pipe[2];
	pid_t newpid;

	/* create pipes */
	if (pipe(cmd_pipe) != 0) {
		qtn_error("create pipe failed (%d)", errno);
		return EX_IOERR;
	}

	if (pipe(resp_pipe) != 0) {
		/* cleanup */
		close(cmd_pipe[0]);
		close(cmd_pipe[1]);
		qtn_error("create pipe failed (%d)", errno);
		return EX_IOERR;
	}

	/* setup signal processing */
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_sigaction = qtn_handle_signal;
	sigact.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGUSR1, &sigact, NULL);

	/* ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* fork into two processes: listener and commands handler */
	newpid = fork();
	if (newpid == 0) {
		/* child */
		close(cmd_pipe[0]);
		close(resp_pipe[1]);

		qtn_run_listener(cmd_pipe[1], resp_pipe[0]);

	} else if (newpid == -1) {
		/* error, cleanup */
		close(cmd_pipe[0]);
		close(cmd_pipe[1]);
		close(resp_pipe[0]);
		close(resp_pipe[1]);
		qtn_error("fork failed (%d)", errno);
		return EX_OSERR;
	} else {
		/* parent */
		close(cmd_pipe[1]);
		close(resp_pipe[0]);
	}

	/* handle commands */
	qtn_run_cmdproc(cmd_pipe[0], resp_pipe[1]);

	kill(newpid, SIGUSR1);

	waitpid(newpid, NULL, 0);

	return EX_OK;
}


static
void qtn_handle_signal(int signum, siginfo_t *siginfo, void *context)
{
	g_qtn_processing = 0;
}


static
int qtn_find_endline(const char *buf_ptr, const int start, const int end)
{
	int i;

	if ((end < 0) || (start < 0) || ((end - start) < 2))
		return -1;

	for (i = start; i < (end - 1); i++)
		if ((buf_ptr[i] == '\r') && (buf_ptr[i+1] == '\n'))
			return i;

	return -1;
}


static
int qtn_read_textline(int fd, char *buf_ptr, int buf_size)
{
	int read_bytes = 0;

	do {
		int endline_pos;

		int nbytes = read(fd, buf_ptr + read_bytes, buf_size - read_bytes);

		if (nbytes <= 0)
			return nbytes;

		read_bytes += nbytes;

		endline_pos = qtn_find_endline(buf_ptr, 0, read_bytes);

		if (endline_pos >= 0) {
			int len = endline_pos + 2;
			buf_ptr[len] = 0;
			return len;
		}

	} while (read_bytes < buf_size);

	return 0;
}


static
int qtn_write_text(int fd, const char *text_ptr, int text_len)
{
	int written_bytes = 0;

	do {
		int nbytes = write(fd, text_ptr + written_bytes, text_len - written_bytes);
		if (nbytes <= 0)
			return nbytes;
		written_bytes += nbytes;
	} while (written_bytes < text_len);

	return written_bytes;
}


static
int qtn_send_text(int sock_fd, const char *text_ptr, int text_len)
{
	int written_bytes = 0;

	do {
		int nbytes = send(sock_fd, text_ptr + written_bytes, text_len - written_bytes,
				MSG_NOSIGNAL);
		if (nbytes <= 0)
			return nbytes;
		written_bytes += nbytes;
	} while (written_bytes < text_len);

	return written_bytes;
}


static
int qtn_run_listener_session(int cli_sock, int server_sock, int cmd_pipe_w, int resp_pipe_r)
{
	int cmd_executing = 0;
	fd_set rset;
	int maxfd = (cli_sock > resp_pipe_r) ? cli_sock : resp_pipe_r;
	char resp_buf[1024];
	int resp_len;
	char req_buf[1024];
	int req_len;
	char cmd_buf[2048];
	int pos_start = 0;
	int pos_end = 0;

	if (server_sock > maxfd) {
		maxfd = server_sock;
	}

	while (g_qtn_processing) {
		FD_ZERO(&rset);
		FD_SET(cli_sock, &rset);
		FD_SET(server_sock, &rset);
		FD_SET(resp_pipe_r, &rset);

		if (select(maxfd + 1, &rset, NULL, NULL, NULL) == -1) {
			if (errno == EINTR) {
				qtn_log("select() interrupted by signal");
				break;
			} else {
				qtn_error("select failed (%d)", errno);
				return -1;
			}
		}

		if (FD_ISSET(server_sock, &rset)) {
			/* new incomming connection, stop handling */
			break;
		}

		if (FD_ISSET(resp_pipe_r, &rset)) {
			/* read response, write back to the client */
			resp_len = qtn_read_textline(resp_pipe_r, resp_buf, sizeof(resp_buf));

			if (resp_len <= 0) {
				qtn_error("read from pipe failed");
				return -1;
			}

			if (qtn_send_text(cli_sock, resp_buf, resp_len) <= 0) {
				qtn_error("send to socket failed");
				break;
			}

			/* clear command processing flag */
			cmd_executing = 0;
		}

		if (FD_ISSET(cli_sock, &rset)) {
			/* read input command */
			int nbytes = recv(cli_sock, cmd_buf + pos_end, sizeof(cmd_buf) - pos_end, 0);
			if (nbytes <= 0) {
				qtn_error("read from socket failed");
				break;
			}

			pos_end += nbytes;

			/* check for command in received buffer */
			while (pos_start < pos_end) {
				int cmd_end = qtn_find_endline(cmd_buf, pos_start, pos_end);

				if (cmd_end == -1)
					break;

				if ((cmd_end > pos_start) && !cmd_executing) {
					cmd_buf[cmd_end] = 0;

					req_len = qtn_recognize_and_parse_command(
							cmd_buf + pos_start,
							req_buf, sizeof(req_buf));

					if (req_len > 0) {
						qtn_log("command: %s", cmd_buf + pos_start);

						/* answer about well formed command */
						resp_len = qtn_encode_response_status(
								STATUS_RUNNING, 0,
								resp_buf, sizeof(resp_buf));

						if (resp_len <= 0) {
							qtn_error("encode response");
							return -1;
						}

						if (qtn_send_text(cli_sock, resp_buf, resp_len) <= 0) {
							qtn_error("send to socket failed");
							break;
						}

						/* send command to parent for further processing */
						if (qtn_write_text(cmd_pipe_w, req_buf, req_len) <= 0) {
							qtn_error("write to pipe failed");
							return -1;
						}

						/* set command processing flag */
						cmd_executing = 1;

					} else {

						/* answer about invalid command */
						resp_len = qtn_encode_response_status(STATUS_INVALID, 1,
								resp_buf, sizeof(resp_buf));

						if (resp_len <= 0) {
							qtn_error("encode response");
							return -1;
						}

						if (qtn_send_text(cli_sock, resp_buf, resp_len) <= 0) {
							qtn_error("send to socket failed");
							break;
						}
					}
				}

				pos_start = cmd_end + 2;
			}

			/* check the buffer */
			if (pos_start) {
				if (pos_start < pos_end) {
					/* shift data left */
					int data_len;
					data_len = pos_end - pos_start;
					memmove(cmd_buf, cmd_buf + pos_start, data_len);
					pos_start = 0;
					pos_end = data_len;

				} else {
					/* reset buffer */
					pos_start = 0;
					pos_end = 0;
				}
			} else if (pos_end >= sizeof(cmd_buf)) {
				/* buffer is full, shift half of buffer */
				int data_len = sizeof(cmd_buf) / 2;
				memmove(cmd_buf, cmd_buf + (sizeof(cmd_buf) - data_len), data_len);
				pos_start = 0;
				pos_end = data_len;
			}
		}
	}

	return 0;
}


static
int qtn_setup_service_conn(struct sockaddr_in *serv_addr)
{
	int sock;
	int optval;

	sock = socket(serv_addr->sin_family, SOCK_STREAM, 0);

	if (sock == -1) {
		qtn_error("socket creation error (%d)", errno);
		return -1;
	}

	optval = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
		qtn_error("socket set option (%d)", errno);
		close(sock);
		return -1;
	}

	if (bind(sock, (const struct sockaddr *)serv_addr, sizeof(*serv_addr)) != 0) {
		qtn_error("bind (%d)", errno);
		close(sock);
		return -1;
	}

	if (listen(sock, QTN_CA_BACKLOG) != 0) {
		qtn_error("listen (%d)", errno);
		close(sock);
		return -1;
	}

	return sock;
}


static
void qtn_run_listener(int cmd_pipe_w, int resp_pipe_r)
{
	struct sockaddr_in serv_addr;
	int serv_sock;
	int cli_sock;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_len;
	int ret;
	const struct qtn_config *cfg = qtn_config_get();

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr = cfg->lsn_addr;
	serv_addr.sin_port = htons(cfg->lsn_port);

	/* server socket */
	serv_sock = qtn_setup_service_conn(&serv_addr);

	if (serv_sock == -1)
		goto cleanup;

	/* wait client connection */
	while(g_qtn_processing) {
		qtn_log("wait client connection");
		cli_addr_len = sizeof(cli_addr);

		cli_sock = accept(serv_sock, (struct sockaddr *)&cli_addr, &cli_addr_len);
		if (cli_sock == -1) {
			if (errno == EINTR) {
				qtn_log("interrupted by signal");
				continue;
			}

			qtn_error("accept (%d)", errno);
			break;
		}

		qtn_log("client connected by %d.%d.%d.%d",
				cli_addr.sin_addr.s_addr & 0xFF,
				(cli_addr.sin_addr.s_addr >> 8) & 0xFF,
				(cli_addr.sin_addr.s_addr >> 16) & 0xFF,
				(cli_addr.sin_addr.s_addr >> 24) & 0xFF);

		ret = qtn_run_listener_session(cli_sock, serv_sock, cmd_pipe_w, resp_pipe_r);

		close(cli_sock);

		if (ret != 0)
			break;

		/* wait a bit before reconnection */
		usleep(50000);
	}

cleanup:
	qtn_log("shutdown listener");

	if (serv_sock != -1)
		close(serv_sock);

	close(cmd_pipe_w);
	close(resp_pipe_r);

	_exit(EX_OK);
}


static
CLIENT *qtn_create_client(const struct qtn_config *cfg)
{
	CLIENT *cli = NULL;

	if (strcasecmp(cfg->dut_proto, "raw") == 0) {
		cli = qrpc_clnt_raw_create(QCSAPI_PROG, QCSAPI_VERS,
					cfg->dut_iface, cfg->dut_mac,
					QRPC_QCSAPI_RPCD_SID);

	} else if ((strcasecmp(cfg->dut_proto, "tcp") == 0)
			|| (strcasecmp(cfg->dut_proto, "udp") == 0)) {
		cli = clnt_create(cfg->dut_addr, QCSAPI_PROG, QCSAPI_VERS, cfg->dut_proto);
	}

	//if (cli) {
	//	struct timeval tv;
	//
	//	tv.tv_sec = 10; /* change timeout to 10 seconds */
	//	tv.tv_usec = 0; /* this should always be set  */
	//	clnt_control(cli, CLSET_TIMEOUT, (char*)&tv);
	//}

	return cli;
}


static
void qtn_run_cmdproc(int cmd_pipe_r, int resp_pipe_w)
{
	CLIENT *clnt;
	fd_set rset;
	int maxfd = cmd_pipe_r;
	char req_buf[1024];
	int req_len;
	char resp_buf[1024];
	int resp_len;
	const struct qtn_config *cfg = qtn_config_get();

	clnt = qtn_create_client(cfg);

	if (!clnt) {
		qtn_error("unable to create RPC client (%d)", errno);
		goto cleanup;
	}

	client_qcsapi_set_rpcclient(clnt);

	/* wait for commands */
	while(g_qtn_processing) {
		FD_ZERO(&rset);
		FD_SET(cmd_pipe_r, &rset);

		if (select(maxfd + 1, &rset, NULL, NULL, NULL) == -1) {
			if (errno == EINTR) {
				qtn_log("select() interrupted by signal");
				continue;
			} else {
				qtn_error("select failed (%d)", errno);
				break;
			}
		}

		if (FD_ISSET(cmd_pipe_r, &rset)) {
			/* read request */
			req_len = qtn_read_textline(cmd_pipe_r, req_buf, sizeof(req_buf));

			if (req_len <= 0) {
				qtn_error("empty command from rxtx");
				break;
			}

			req_buf[req_len] = 0;

			/* execute command */
			resp_len = qtn_dispatch_request(req_buf, resp_buf, sizeof(resp_buf));

			if (resp_len > 0) {
				/* return response */
				if (qtn_write_text(resp_pipe_w, resp_buf, resp_len) <= 0) {
					qtn_error("write to pipe failed");
					break;
				}

			} else {
				/* not supported */
				qtn_error("command not supported");

				/* answer about invalid command */
				resp_len = qtn_encode_response_status(STATUS_INVALID, EOPNOTSUPP,
						resp_buf, sizeof(resp_buf));

				if (resp_len <= 0) {
					qtn_error("encode response");
					break;
				}

				if (qtn_write_text(resp_pipe_w, resp_buf, resp_len) <= 0) {
					qtn_error("send to socket failed");
					break;
				}
			}
		}
	}

cleanup:
	qtn_log("shutdown command processing");

	close(cmd_pipe_r);
	close(resp_pipe_w);

	if (clnt)
		clnt_destroy(clnt);
}
