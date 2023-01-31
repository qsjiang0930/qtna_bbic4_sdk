/**
* Copyright (c) 2016 Quantenna Communications, Inc.
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

#include "qproc_mon.h"

static struct qproc_mon_state qproc_mon = {.conn_sock = -1, .launch_fifo_fd = -1,
						.launch_mqid = -1, .active_list = NULL,
						.pending_list = NULL};
static int verbosity_flag = 0;

static void _qproc_mon_log_message(int level, const char *fmt, ...)
{
	va_list arg;
	int priority;

	va_start(arg, fmt);

	if ((level == MESG_ERROR) || verbosity_flag) {
		priority = (level == MESG_ERROR) ? LOG_ERR : LOG_INFO;
		vsyslog(priority, fmt, arg);
		vfprintf(stderr, fmt, arg);
	}

	va_end(arg);
}

void qproc_mon_sigchild_handler(int sig)
{
	pid_t pid;
	int status;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) {
			if (errno == EINTR) {
				continue;
			}
			break;
		} else if (pid == 0) {
			break;
		}
	}
}

static int qproc_mon_set_event_listener(int nl_sock, bool enable)
{
	struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
		struct nlmsghdr nl_hdr;
		struct __attribute__ ((__packed__)) {
			struct cn_msg cn_msg;
			enum proc_cn_mcast_op cn_mcast;
		};
	} nlcn_msg;

	memset(&nlcn_msg, 0, sizeof(nlcn_msg));
	nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
	nlcn_msg.nl_hdr.nlmsg_pid = getpid();
	nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

	nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
	nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
	nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

	nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

	if (send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0) == -1) {
		log_message(MESG_ERROR, "Failed to send netlink connector socket message");
		return -1;
	}

	return 0;
}

static int qproc_mon_process_exists(pid_t pid)
{
	char buf[QPROC_MON_MAX_CMD_LEN];
	struct stat sts;

	snprintf(buf, sizeof(buf), "/proc/%d", pid);
	if (stat(buf, &sts) == 0 && S_ISDIR(sts.st_mode)) {
		return 0;
	}

	return -1;
}

static void qproc_mon_delete_pid_nodes(struct qproc_mon_pid_node **phead)
{
	struct qproc_mon_pid_node *tmp;

	while (*phead != NULL) {
		tmp = *phead;
		*phead = (*phead)->next;
		free(tmp);
	}
}

static void qproc_mon_delete_proc_nodes(struct qproc_mon_node **phead)
{
	struct qproc_mon_node *tmp;

	while (*phead != NULL) {
		qproc_mon_delete_pid_nodes(&(*phead)->pid_head);

		tmp = *phead;
		*phead = (*phead)->next;
		free(tmp);
	}
}

static int qproc_mon_create_pipe(int *pfd)
{
	int flags;

	if (pipe(pfd) == -1) {
		log_message(MESG_ERROR, "Failed to create pipe: %s", strerror(errno));
		return -1;
	}

	flags = fcntl(pfd[1], F_GETFD, 0);
	if (flags < 0) {
		log_message(MESG_ERROR, "Failed to get flags using fcntl: %s", strerror(errno));
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	if (fcntl(pfd[1], F_SETFD, flags | FD_CLOEXEC) < 0) {
		log_message(MESG_ERROR, "Failed to set flags using fcntl: %s", strerror(errno));
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	return 0;
}

static pid_t qproc_mon_launch_process(char *cmd_args)
{
	int i;
	char *arg;
	char *params[QPROC_MON_MAX_ARGS];
	pid_t pid;
	char cmd_line[QPROC_MON_MAX_CMD_LEN];
	int pfd[2];
	int ret;
	int child_ret = 0;

	strncpy(cmd_line, cmd_args, sizeof(cmd_line) - 1);
	cmd_line[sizeof(cmd_line) - 1] = '\0';

	arg = strtok(cmd_line, " ");
	for (i = 0; arg != NULL; i++) {
		if (i >= QPROC_MON_MAX_ARGS - 1) {
			log_message(MESG_ERROR, "Number of arguments exceeded");
			return -1;
		}
		params[i] = arg;
		arg = strtok(NULL, " ");
	}

	if (i == 0)
		return -1;

	params[i] = NULL;

	/* Create pipe to get return value from execvp of child */
	if (qproc_mon_create_pipe(pfd) < 0)
		return -1;

	while ((pid = vfork()) == -1)
		usleep(500);

	if (pid == 0) {
		close(qproc_mon.launch_fifo_fd);
		close(pfd[0]);
		ret = execvp(params[0], params);
		write(pfd[1], &ret, sizeof(ret));
		close(pfd[1]);
		_exit(0);
	}

	close(pfd[1]);
	ret = read(pfd[0], &child_ret, sizeof(child_ret));
	close(pfd[0]);
	if (ret < 0) {
		log_message(MESG_ERROR, "Failed to read child return value");
		return -1;
	}

	if (child_ret < 0) {
		log_message(MESG_ERROR, "Exec failed");
		return -1;
	}

	return pid;
}

static int qproc_mon_update_persistent_file(void)
{
	struct qproc_mon_node *tmp = qproc_mon.active_list;
	struct qproc_mon_pid_node *pid_node;
	FILE *write_fp;

	write_fp = fopen(QPROC_MON_STATE_FILE_TEMP, "w");
	if (write_fp == NULL) {
		log_message(MESG_ERROR, "Failed to open temp persistent file: %s : %s",
					QPROC_MON_STATE_FILE_TEMP, strerror(errno));
		return -1;
	}

	while (tmp != NULL) {
		pid_node = tmp->pid_head;
		while (pid_node->next != NULL) {
			fprintf(write_fp, "%d,", pid_node->pid);
			pid_node = pid_node->next;
		}
		fprintf(write_fp, "%d:%d:%s\n", pid_node->pid, tmp->exec_flag, tmp->cmd_args);
		tmp = tmp->next;
	}

	fclose(write_fp);

	if (rename(QPROC_MON_STATE_FILE_TEMP, QPROC_MON_STATE_FILE) < 0) {
		log_message(MESG_ERROR, "Failed rename file %s to %s : %s",
				QPROC_MON_STATE_FILE_TEMP, QPROC_MON_STATE_FILE, tmp->cmd_args);
		return -1;
	}

	return 0;
}

static int qproc_mon_add_persistent_file(struct qproc_mon_node *proc_node)
{
	FILE *fp;

	fp = fopen(QPROC_MON_STATE_FILE, "a");
	if (fp == NULL) {
		log_message(MESG_ERROR, "Failed to open persistent file: %s : %s",
					QPROC_MON_STATE_FILE, strerror(errno));
		return -1;
	}

	fprintf(fp, "%d:%d:%s\n", proc_node->pid_head->pid, proc_node->exec_flag, proc_node->cmd_args);

	fclose(fp);
	return 0;
}

static void qproc_mon_send_event(char *cmd_args, int exit_code)
{
	char process_exit_cmd[QEVT_MAX_MSG_LEN];
	char *process_name;
	char cmd_line[QPROC_MON_MAX_CMD_LEN];

	strncpy(cmd_line, cmd_args, sizeof(cmd_line) - 1);
	cmd_line[sizeof(cmd_line) - 1] = '\0';

	process_name = strtok(cmd_line, " ");
	if (process_name == NULL)
		return;

	snprintf(process_exit_cmd, QEVT_MAX_MSG_LEN, QEVT_SEND_EVENT_CMD " \""QEVT_COMMON_PREFIX
					"System process exited %s %d\"", process_name, exit_code);
	if (system(process_exit_cmd) != 0) {
		log_message(MESG_ERROR, "Failed to send process exit event message qevt_server");
	}
}

static int qproc_mon_add_pid_node(struct qproc_mon_pid_node **pid_head, pid_t pid)
{
	struct qproc_mon_pid_node *temp;

	temp = (struct qproc_mon_pid_node *) malloc(sizeof(struct qproc_mon_pid_node));
	if (temp == NULL) {
		log_message(MESG_ERROR, "Failed allocate memory for pid node");
		return -ENOMEM;
	}
	temp->pid = pid;
	temp->next = *pid_head;
	*pid_head = temp;

	return 0;
}

static int qproc_mon_restart_process(struct qproc_mon_node *qprocess, int exit_code)
{
	pid_t pid;

	qproc_mon_send_event(qprocess->cmd_args, exit_code);
	pid = qproc_mon_launch_process(qprocess->cmd_args);
	if (pid > 0) {
		qproc_mon_add_pid_node(&qprocess->pid_head, pid);
	} else {
		log_message(MESG_ERROR, "Failed to restart process: %s", qprocess->cmd_args);
	}

	return 0;
}

static void qproc_mon_handle_exit_event(struct qproc_mon_node *head, struct exit_proc_event *exit_event)
{
	struct qproc_mon_pid_node *cur;
	struct qproc_mon_pid_node *prev;

	while (head != NULL) {
		prev = NULL;
		cur = head->pid_head;
		while (cur != NULL && cur->pid != exit_event->process_pid) {
			prev = cur;
			cur = cur->next;
		}

		if (cur == NULL) {
			head = head->next;
			continue;
		}

		log_message(MESG_INFO, "EXIT: pid=%d exit_code=%d exit_signal %d",
				exit_event->process_pid, exit_event->exit_code, exit_event->exit_signal);

		if (prev == NULL) {
			/* First pid node */
			if (cur->next == NULL) {
				log_message(MESG_INFO,"Restarting exited process %d : %s",
						exit_event->process_pid, head->cmd_args);
				head->pid_head = NULL;
				head->exec_flag = 0;
				qproc_mon_restart_process(head, exit_event->exit_code);
			} else {
				head->pid_head = cur->next;
			}
		} else {
			prev->next = cur->next;
		}

		free(cur);
		qproc_mon_update_persistent_file();

		return;
	}
}

static void qproc_mon_handle_exec_event(struct qproc_mon_node *head, struct exec_proc_event *exec_event)
{
	struct qproc_mon_pid_node *cur;
	struct qproc_mon_pid_node *prev;

	while (head != NULL) {
		prev = NULL;
		cur = head->pid_head;
		while (cur != NULL && cur->pid != exec_event->process_pid) {
			prev = cur;
			cur = cur->next;
		}

		if (cur == NULL) {
			head = head->next;
			continue;
		}

		log_message(MESG_INFO, "EXEC: pid=%d tgid=%d",
				exec_event->process_pid, exec_event->process_tgid);

		if (prev == NULL && cur->next == NULL) {
			log_message(MESG_INFO,"Initial exec event %d : %s",
					exec_event->process_pid, head->cmd_args);
			head->exec_flag = 1;
		} else {
			/* exec_flag will be set when qproc_mon calls exec and
			 * receives EXEC event for its monitoring process.
			 * If EXEC event is received for its child process
			 * delete child pid node.
			 */
			if (head->exec_flag) {
				if (prev == NULL) {
					head->pid_head = cur->next;
				} else {
					prev->next = cur->next;
				}
				free(cur);
			}
		}

		qproc_mon_update_persistent_file();

		return;
	}
}

static void qproc_mon_handle_fork_event(struct qproc_mon_node *head, struct fork_proc_event *fork_event)
{
	struct qproc_mon_pid_node *cur;

	while (head != NULL) {
		cur = head->pid_head;
		while (cur != NULL && cur->pid != fork_event->parent_pid) {
			cur = cur->next;
		}

		if (cur == NULL) {
			head = head->next;
			continue;
		}

		log_message(MESG_INFO, "FORK: pid=%d child pid=%d", fork_event->parent_pid,
				fork_event->child_pid);
		qproc_mon_add_pid_node(&head->pid_head, fork_event->child_pid);
		qproc_mon_update_persistent_file();

		return;
	}
}

static int qproc_mon_handle_process_events()
{
	int ret;
	struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
		struct nlmsghdr nl_hdr;
		struct __attribute__ ((__packed__)) {
			struct cn_msg cn_msg;
			struct proc_event proc_ev;
		};
	} nlcn_msg;

	ret = recv(qproc_mon.conn_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
	if (ret <= 0) {
		log_message(MESG_ERROR, "Failed to recv netlink connector event");
		return ret;
	}

	switch (nlcn_msg.proc_ev.what) {
	case PROC_EVENT_EXIT:
		qproc_mon_handle_exit_event(qproc_mon.active_list, &nlcn_msg.proc_ev.event_data.exit);
		break;
	case PROC_EVENT_EXEC:
		qproc_mon_handle_exec_event(qproc_mon.active_list, &nlcn_msg.proc_ev.event_data.exec);
		break;
	case PROC_EVENT_FORK:
		qproc_mon_handle_fork_event(qproc_mon.active_list, &nlcn_msg.proc_ev.event_data.fork);
		break;
	default:
		break;
	}

	return ret;
}

static struct qproc_mon_node *qproc_mon_add_to_list(struct qproc_mon_node **phead,
				struct qproc_mon_pid_node *pid_head, int exec_flag, char *cmd_args)
{
	struct qproc_mon_node *tmp;

	tmp = (struct qproc_mon_node *) malloc(sizeof(struct qproc_mon_node));
	if (tmp == NULL) {
		log_message(MESG_ERROR, "Failed to allocate memory for process entry: cmd %s", cmd_args);
		return NULL;
	}
	log_message(MESG_INFO, "Creating node with: %s", cmd_args);

	tmp->exec_flag = exec_flag;
	tmp->pid_head = pid_head;
	memset(tmp->cmd_args, '\0', sizeof(tmp->cmd_args));
	strncpy(tmp->cmd_args, cmd_args, sizeof(tmp->cmd_args) - 1);

	tmp->next = *phead;
	*phead = tmp;

	return tmp;
}

static int qproc_mon_process_launch_start_event(char *cmd_buf)
{
	pid_t pid;
	struct qproc_mon_node *tmp;

	pid = qproc_mon_launch_process(cmd_buf);
	if (pid <= 0) {
		log_message(MESG_ERROR, "Failed to start process: %s", cmd_buf);
		return -1;
	}

	tmp = qproc_mon_add_to_list(&qproc_mon.active_list, NULL, 0, cmd_buf);
	if (tmp == NULL)
		return -1;

	qproc_mon_add_pid_node(&tmp->pid_head, pid);

	qproc_mon_add_persistent_file(tmp);

	return 0;
}

static int qproc_mon_cmp_process_name(char *name, char *cmd_args)
{
	char *process_name;
	char cmd_line[QPROC_MON_MAX_CMD_LEN];

	strncpy(cmd_line, cmd_args, sizeof(cmd_line) - 1);
	cmd_line[sizeof(cmd_line) - 1] = '\0';

	process_name = strtok(cmd_line, " ");
	if (process_name == NULL)
		return 1;

	return strcmp(name, process_name);
}

static int qproc_mon_remove_from_list(struct qproc_mon_node **phead, char *cmd_name)
{
	struct qproc_mon_node *cur = *phead;
	struct qproc_mon_node *prev = NULL;
	struct qproc_mon_node *tmp;
	int update = 0;

	while (cur) {
		if (qproc_mon_cmp_process_name(cmd_name, cur->cmd_args)) {
			prev = cur;
			cur = cur->next;
			continue;
		}

		tmp = cur;
		if (prev == NULL) {
			*phead = cur->next;
		} else {
			prev->next = cur->next;
		}

		qproc_mon_delete_pid_nodes(&tmp->pid_head);
		cur = cur->next;
		free(tmp);
		update = 1;
	}

	return update;
}

static void qproc_mon_kill_process(char *name)
{
	char *process_name;
	char kill_cmd[QPROC_MON_MAX_CMD_LEN];

	process_name = strrchr(name, '/');
	if (process_name == NULL) {
		process_name = name;
	} else {
		process_name++;
	}

	snprintf(kill_cmd, QPROC_MON_MAX_CMD_LEN, "killall %s", process_name);
	system(kill_cmd);
	/* FIXME To remove zombie entries from process table */
	qproc_mon_sigchild_handler(SIGCHLD);
}

static void qproc_mon_process_launch_stop_event(char *buffer)
{
	if (qproc_mon_remove_from_list(&qproc_mon.active_list, buffer)) {
		qproc_mon_update_persistent_file();
		qproc_mon_kill_process(buffer);
	}

	qproc_mon_remove_from_list(&qproc_mon.pending_list, buffer);
}

static void qproc_mon_process_config_event(unsigned int	cfg_type, char *cfg_val)
{
	/* configuration setting */
	switch (cfg_type) {
	case QPROC_MON_CONFIG_VERBOSITY_MSG_TYPE:
		/* verbosity of debug messages */
		switch (cfg_val[0]) {
		case '0':
		case 'F':
		case 'f':
		case 'N':
		case 'n':
			/* 0 or [Ff]alse or [Nn]o */
			verbosity_flag = 0;
			break;
		case '1':
		case 'T':
		case 't':
		case 'Y':
		case 'y':
			/* 1 or [Tt]rue or [Yy]es */
			verbosity_flag = 1;
			break;
		}
		break;
	}
}

static int qproc_mon_handle_launch_events(void)
{
	struct qproc_mon_message msg = {0};
	int len;

	len = read(qproc_mon.launch_fifo_fd, &msg, sizeof(msg));
	if (len > 0) {
		if (msg.cmd_args_len >= QPROC_MON_MAX_CMD_LEN) {
			log_message(MESG_ERROR, "Command length is too long: %d", msg.cmd_args_len);
			return -1;
		}

		msg.cmd_args[msg.cmd_args_len] = '\0';
		if (msg.type == QPROC_MON_LAUNCH_START_MSG_TYPE) {
			qproc_mon_process_launch_start_event(msg.cmd_args);
		} else if (msg.type == QPROC_MON_LAUNCH_STOP_MSG_TYPE) {
			qproc_mon_process_launch_stop_event(msg.cmd_args);
		} else if (msg.type == QPROC_MON_CONFIG_VERBOSITY_MSG_TYPE) {
			qproc_mon_process_config_event(msg.type, msg.cmd_args);
		} else {
			return -1;
		}
	}

	return 0;
}

static int qproc_mon_process_pending_launch_event(void)
{
	pid_t pid;
	struct qproc_mon_node *list = qproc_mon.pending_list;
	struct qproc_mon_node *tmp;

	while (list != NULL) {
		tmp = list;
		list = list->next;

		pid = qproc_mon_launch_process(tmp->cmd_args);
		if (pid <= 0) {
			log_message(MESG_ERROR, "Failed to start process: %s", tmp->cmd_args);
			free(tmp);
			continue;
		}
		qproc_mon_add_pid_node(&tmp->pid_head, pid);
		tmp->next = qproc_mon.active_list;
		qproc_mon.active_list = tmp;
	}

	qproc_mon.pending_list = NULL;

	return qproc_mon_update_persistent_file();
}

static int qproc_mon_wait_for_events(void)
{
	int ret = 0;
	int last_fd = 0;
	fd_set rfds;
	struct timeval tv;

	while (1) {

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);

		if (qproc_mon.conn_sock >= 0) {
			FD_SET(qproc_mon.conn_sock, &rfds);
			last_fd = qproc_mon.conn_sock;
		}

		if (qproc_mon.launch_fifo_fd >= 0) {
			FD_SET(qproc_mon.launch_fifo_fd, &rfds);
			last_fd = MAX(last_fd, qproc_mon.launch_fifo_fd);
		}

		/* Wait until something happens */
		ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			log_message(MESG_ERROR, "Unhandled select event - exiting");
			break;
		}

		if (ret == 0) {
			continue;
		}

		if (qproc_mon.conn_sock >= 0 && FD_ISSET(qproc_mon.conn_sock, &rfds)) {
			qproc_mon_handle_process_events();
		}

		if (qproc_mon.launch_fifo_fd >= 0 && FD_ISSET(qproc_mon.launch_fifo_fd, &rfds)) {
			qproc_mon_handle_launch_events();
		}

		if (qproc_mon.pending_list != NULL) {
			qproc_mon_process_pending_launch_event();
		}
	}

	return ret;
}

static int qproc_mon_parse_persistent_file(void)
{
	FILE *fp = NULL;
	size_t len = 0;
	char *line = NULL;
	size_t read_l;
	struct qproc_mon_node *tmp = NULL;
	struct qproc_mon_pid_node *pid_list = NULL;
	int ret = 0;
	int exec_flag;
	char *pos;
	pid_t pid;

	fp = fopen(QPROC_MON_STATE_FILE, "r");
	if (fp == NULL) {
		log_message(MESG_ERROR, "Failed to open process monitor configuration file: %s : %s",
				QPROC_MON_STATE_FILE, strerror(errno));
		return -1;
	}

	log_message(MESG_INFO, "Reading configuration file");

	while ((read_l = getline(&line, &len, fp)) != -1) {
		if (line[read_l - 1] == '\n')
			line[read_l - 1] = '\0';

		/* Format for persistent file entry => ProcessID1,ProcessID2,..:Execflag:CommandLineArgs */
		/* Get Process IDs */
		pos = strtok(line, ":");
		if (pos == NULL) {
			log_message(MESG_ERROR, "Persistent file is corrupted");
			goto failure;
		}

		while (*pos != '\0') {
			pid = atoi(pos);
			if (qproc_mon_process_exists(pid) == 0) {
				qproc_mon_add_pid_node(&pid_list, pid);
			}

			while (*pos != ',' && *pos != '\0')
				pos++;

			if (*pos == ',')
				pos++;
		}

		/* Get EXEC flag */
		pos = strtok(NULL, ":");
		if (pos == NULL) {
			log_message(MESG_ERROR, "Persistent file is corrupted");
			goto failure;
		}

		exec_flag = atoi(pos);

		/* Get Command args */
		pos = strtok(NULL, ":");
		if (pos == NULL) {
			log_message(MESG_ERROR, "Persistent file is corrupted");
			goto failure;
		}

		if (strlen(pos) >= QPROC_MON_MAX_CMD_LEN) {
			log_message(MESG_ERROR, "command args length is too long: %s\n", pos);
			goto failure;
		}

		if (pid_list == NULL) {
			qproc_mon_add_to_list(&qproc_mon.pending_list, NULL, 0, pos);
			continue;
		}

		tmp = qproc_mon_add_to_list(&qproc_mon.active_list, pid_list, exec_flag, pos);
		if (tmp == NULL) {
			ret = -1;
			goto failure;
		}

		log_message(MESG_INFO, "%s", line);
		pid_list = NULL;
	}

	ret = qproc_mon_update_persistent_file();

failure:
	if (pid_list)
		qproc_mon_delete_pid_nodes(&pid_list);

	if (line)
		free(line);

	fclose(fp);

	return ret;
}

static int qproc_mon_handle_pre_spawn_launch_events(void)
{
	struct qproc_mon_mq_buffer cmd_buf;
	struct qproc_mon_message *msg;
	struct msqid_ds stats;
	int len;

	if (msgctl(qproc_mon.launch_mqid, IPC_STAT, &stats) == -1) {
		log_message(MESG_ERROR, "Failed msgctl: %s", strerror(errno));
		return -1;
	}

	while (stats.msg_qnum > 0) {
		memset(&cmd_buf, 0, sizeof(cmd_buf));

		/* Message type is 0 to receive first message in queue */
		/* sizeof(*msg) == sizeof(cmd_buf.message), so it's not overrun-buffer. */
		/* coverity[overrun-buffer-arg] */
		len = msgrcv(qproc_mon.launch_mqid, &cmd_buf, sizeof(*msg), 0, IPC_NOWAIT);
		if (len < 0) {
			log_message(MESG_ERROR, "Failed msgrcv: %s", strerror(errno));
			return -1;
		}

		stats.msg_qnum--;
		msg = &cmd_buf.message;

		if (msg->cmd_args_len >= QPROC_MON_MAX_CMD_LEN) {
			log_message(MESG_ERROR, "Command length is too long: %d", msg->cmd_args_len);
			continue;
		}

		msg->cmd_args[msg->cmd_args_len] = '\0';

		if (msg->type == QPROC_MON_LAUNCH_START_MSG_TYPE) {
			qproc_mon_add_to_list(&qproc_mon.pending_list, NULL, 0, msg->cmd_args);
		} else if (msg->type == QPROC_MON_LAUNCH_STOP_MSG_TYPE) {
			qproc_mon_process_launch_stop_event(msg->cmd_args);
		} else if (msg->type == QPROC_MON_CONFIG_VERBOSITY_MSG_TYPE) {
			qproc_mon_process_config_event(msg->type, msg->cmd_args);
		}

	}

	return 0;
}

static int qproc_mon_nl_connector_init(void)
{
	int ret;
	int nl_sock;
	struct sockaddr_nl sa_nl;

	nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (nl_sock == -1) {
		log_message(MESG_ERROR, "Failed to create netlink connector socket");
		return -1;
	}

	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	ret = bind(nl_sock, (struct sockaddr *) &sa_nl, sizeof(sa_nl));
	if (ret == -1) {
		log_message(MESG_ERROR, "Failed to bind netlink connector socket");
		close(nl_sock);
		return ret;
	}

	ret = qproc_mon_set_event_listener(nl_sock, true);
	if (ret == -1) {
		close(nl_sock);
		return ret;
	}

	qproc_mon.conn_sock = nl_sock;

	return 0;
}

static int qproc_mon_launch_recv_init(void)
{
	key_t key;

	key = ftok(QPROC_MON_CONFIG, QPROC_MON_PROJ_ID);
	if (key == -1) {
		log_message(MESG_ERROR, "Failed to get key in ftok");
		return -1;
	}

	qproc_mon.launch_mqid = msgget(key, IPC_CREAT | 0666);
	if (qproc_mon.launch_mqid < 0) {
		log_message(MESG_ERROR, "Failed to initialize launch message queue: %s", strerror(errno));
		return -1;
	}

	/* TODO: Do we need to set any options for the queue */

	return 0;
}

static int qproc_mon_launch_event_fifo_init(void)
{
	int ret;

	(void) remove(QPROC_MON_FIFO);

	ret = mkfifo(QPROC_MON_FIFO, 0666);
	if (ret < 0) {
		log_message(MESG_ERROR, "Failed to create mkfifo: %s", strerror(errno));
		return -1;
	}

	qproc_mon.launch_fifo_fd = open(QPROC_MON_FIFO, O_RDWR | O_NONBLOCK);
	if (qproc_mon.launch_fifo_fd < 0) {
		log_message(MESG_ERROR, "Failed to open fifo file: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void qproc_mon_cleanup(void)
{
	if (qproc_mon.conn_sock != -1) {
		qproc_mon_set_event_listener(qproc_mon.conn_sock, false);
		close(qproc_mon.conn_sock);
	}

	qproc_mon_delete_proc_nodes(&qproc_mon.active_list);
	qproc_mon_delete_proc_nodes(&qproc_mon.pending_list);

	if (qproc_mon.launch_fifo_fd > 0)
		close(qproc_mon.launch_fifo_fd);

	closelog();
}

static int qproc_mon_init(void)
{
	openlog("qproc_mon", LOG_PID | LOG_NDELAY, LOG_USER);

	log_message(MESG_INFO, "Starting process monitor log messages...");

	if (qproc_mon_nl_connector_init() < 0)
		return -1;

	if (qproc_mon_launch_event_fifo_init() < 0)
		return -1;

	/* Launch message queue receiver initialization */
	if (qproc_mon_launch_recv_init() < 0)
		return -1;

	qproc_mon_parse_persistent_file();

	qproc_mon_handle_pre_spawn_launch_events();

	signal(SIGCHLD, qproc_mon_sigchild_handler);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	int opt;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
		case 'v':
			verbosity_flag = 1;
			break;
		default:
			/* ignore unknown options */
			break;
               }
	}

	ret = qproc_mon_init();
	if (ret == 0) {
		qproc_mon_wait_for_events();
	}

	qproc_mon_cleanup();

	return ret;
}
