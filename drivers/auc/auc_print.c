/**
 * Copyright (c) 2009 - 2017 Quantenna Communications Inc
 * All Rights Reserved
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

#include <linux/version.h>
#include <linux/syscalls.h>
#include <qtn/qtn_debug.h>
#include <qtn/shared_print_buf.h>

MODULE_DESCRIPTION("Quantenna AuC print driver");
MODULE_AUTHOR("Quantenna Communications Inc.");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

#define AUC_PREFIX	"AuC"

unsigned (*uc_print_auc_cb)(struct shared_print_consumer* shared_buf, unsigned max_lines) = NULL;
EXPORT_SYMBOL(uc_print_auc_cb);

#if AUC_LHOST_PRINT_FORMAT
static unsigned uc_print_auc(struct shared_print_consumer* shared_buf, unsigned max_lines);
#endif

static int __init qdrv_uc_print_auc_init(void)
{
#if AUC_LHOST_PRINT_FORMAT
	uc_print_auc_cb = uc_print_auc;
#endif
	return 0;
}

static void __exit qdrv_uc_print_auc_exit(void)
{
	uc_print_auc_cb = NULL;
}

module_init(qdrv_uc_print_auc_init);
module_exit(qdrv_uc_print_auc_exit);

#if AUC_LHOST_PRINT_FORMAT

static void auc_tx_dump_raw_data(void *data, size_t sz, uint32_t auc_p);
static void auc_tx_dump_tqew_descr(void *descr, size_t sz, uint32_t auc_p);
static void auc_tx_dump_mpdu_hdr_descr(void *descr, size_t sz, uint32_t auc_p);
static void auc_tx_dump_msdu_hdr_descr(void *descr, size_t sz, uint32_t auc_p);
static void auc_tx_dump_txstatus(void *status, size_t sz, uint32_t auc_p);
static void auc_tx_dump_fcs(void *fcs, size_t sz, uint32_t auc_p);
static void auc_tx_dump_mac_descr(void *mac_descr, size_t sz, uint32_t auc_p);

typedef enum {
	AFT_MAC_DESCR	= 0,
	AFT_FCS		= 1,
	AFT_TXSTATUS	= 2,
	AFT_TQEWD	= 3,
	AFT_MPDU_DESCR	= 4,
	AFT_MSDU_DESCR	= 5,
	AFT_RAW		= 6, /*should be at the end*/
	AFT_DEFAULT	= 7, /*should be at the end*/
	AFT_NUM		= AFT_DEFAULT
} auc_format_type;

typedef void	(*print_struct)(void *data, size_t sz, uint32_t auc_p);

struct format_str {
	char		format[4];
	unsigned	arg_stack_size;
	print_struct	f;
};

#define AUC_DUMP_ARGS_SIZE (2 * sizeof(uint32_t))
static const struct format_str format_map[] = {
	/*AFT_MAC_DESCR*/
	{"%md",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_mac_descr},
	/*AFT_FCS*/
	{"%fc",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_fcs},
	/*AFT_TXSTATUS*/
	{"%ts",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_txstatus},
	/*AFT_TQEWD*/
	{"%td",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_tqew_descr},
	/*AFT_MPDU_DESCR*/
	{"%pd",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_mpdu_hdr_descr},
	/*AFT_MSDU_DESCR*/
	{"%sd",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_msdu_hdr_descr},
	/*AFT_RAW*/
	{"%aa",	AUC_DUMP_ARGS_SIZE,	(void*)auc_tx_dump_raw_data},
	/*AFT_DEFAULT*/
	{"",	PRINT_STACK_SIZE,	NULL}
};

/*
 * the uC acts as a producer, writing data into the buffer and updating a count of
 * bytes written. This function acts as a sole consumer, reading data from the
 * uC's buffer line by line.
 *
 * The producer is not aware of the consumer(s), so failure to consume bytes quickly enough
 * result in lost printouts
 */
static unsigned uc_print_auc(struct shared_print_consumer* shared_buf, unsigned max_lines)
{
#define FW_PRINT_MAX_CHAR_PER_LINE	128
	char buf[FW_PRINT_MAX_CHAR_PER_LINE];
	uint32_t *args;
	char stackbuf[2 * FW_PRINT_MAX_CHAR_PER_LINE];
	int took_line;
	uint32_t args_size = 0, args_size_x = 0;
	auc_format_type type;
	const uint32_t bufsize = shared_buf->producer->bufsize;
	const uint32_t produced = shared_buf->producer->produced % bufsize;
	volatile const char *print_buf = shared_buf->buf;
	uint32_t consumed = shared_buf->consumed;
	unsigned completed_lines = 0;
	uint32_t print_packet_len;

	if (produced == consumed)
		return max_lines;

	for (took_line = 1; took_line && completed_lines < max_lines; ) {
		uint32_t chars_to_consume = produced - consumed;
		uint32_t i;

		took_line = 0;
		type = AFT_DEFAULT;
		args = NULL;

		if (chars_to_consume == 0)
			break;

		if (produced < consumed)
			chars_to_consume += bufsize;

		--chars_to_consume;

		print_packet_len = print_buf[consumed];
		consumed++;
		if (consumed == bufsize)
			consumed = 0;

		if (chars_to_consume < print_packet_len)
			break;

		if (print_packet_len > (uint32_t)sizeof(buf)) {
			printk(KERN_ERR "%s: %s\n", AUC_PREFIX, "Printed string is too large");

			consumed += print_packet_len;
			if (consumed >= bufsize)
				consumed -= bufsize;

			took_line = 1;
			break;
		}

		for (i = 0; i < print_packet_len; i++) {
			char c;

			c = print_buf[consumed];
			++consumed;
			if (consumed == bufsize)
				consumed = 0;

			buf[i] = c;

			if (!args && c == '\0') {
				/* We've done with format. Arguments follow */
				args_size = print_packet_len - i - 1;
				args = (uint32_t *)&buf[i + 1];

				for (type = 0; type < AFT_NUM &&
					strcmp(buf, format_map[type].format) != 0; type++);
			}
		}

		/* Processing arguments */
		if (args) {
			if (type <= AFT_RAW) {
				args_size_x = format_map[type].arg_stack_size + args[0];

				if (args_size > args_size_x)
					format_map[type].f((void *)&args[2], args[0], args[1]);
			} else {
				/*
				 * args points to the first 32-bit argument word in an array.
				 * 8 argument words are passed always, not depending on the format.
				 */
				vsnprintf(stackbuf, sizeof(stackbuf), buf, (void *)args);
				printk(KERN_INFO AUC_PREFIX": %s", stackbuf);
			}
		}

		took_line = 1;
		++completed_lines;
		args = NULL;
	}
	shared_buf->consumed = consumed;

	return max_lines - completed_lines;
}

static void
auc_tx_dump_raw_data(void *data, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": raw data: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 1, data, sz, false);
}

static void
auc_tx_dump_tqew_descr(void *descr, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": tqew descr: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 1, descr, sz, false);
}

static void
auc_tx_dump_mpdu_hdr_descr(void *descr, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": mpdu_hdr: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 1, descr, sz, false);
}

static void
auc_tx_dump_msdu_hdr_descr(void *descr, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": msdu_hdr: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 1, descr, sz, false);
}

static void
auc_tx_dump_txstatus(void *status, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": txstatus structure: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 4, status, sz, false);
}

static void
auc_tx_dump_fcs(void *fcs, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": frame control structure: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 4, fcs, sz, false);
}

static void
auc_tx_dump_mac_descr(void *descr, size_t sz, uint32_t auc_p)
{
	printk(KERN_INFO AUC_PREFIX": mac_descr: %08x\n", auc_p);
	print_hex_dump(KERN_INFO, AUC_PREFIX": ", DUMP_PREFIX_OFFSET, 16, 1, descr, sz, false);
}

#endif

