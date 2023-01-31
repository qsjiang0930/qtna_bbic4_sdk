/**
  Copyright (c) 2016 - 2017 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 **/

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <qtn/qtn_bb_mutex.h>
#include <asm/io.h>

MODULE_DESCRIPTION("Hardware revision");
MODULE_AUTHOR("Quantenna Communications, Inc.");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

static int hw_info_get_reboot_cause(void)
{
	return readl(TOPAZ_SYS_CTL_RESET_CAUSE);
}

static unsigned int hw_rev = HARDWARE_REVISION_UNKNOWN;
static int read_hardware_rev(void)
{
	int ret = HARDWARE_REVISION_UNKNOWN;
	uint32_t board_rev;

	board_rev = *(volatile unsigned int *)(RUBY_SYS_CTL_CSR);

	if ((board_rev & CHIP_ID_MASK) == CHIP_ID_TOPAZ) {
		switch (board_rev & CHIP_REV_ID_MASK) {
			case REV_ID_TOPAZ_A:
				ret = HARDWARE_REVISION_TOPAZ_A;
				break;
			case REV_ID_TOPAZ_B:
				ret = HARDWARE_REVISION_TOPAZ_B;
				break;
			case REV_ID_TOPAZ_A2:
				ret = HARDWARE_REVISION_TOPAZ_A2;
				break;
		}
	}

	return ret;
}

static int hw_rev_proc_show(struct seq_file *m, void *v)
{
	const char *hw_ver_descs[] = {
		[HARDWARE_REVISION_UNKNOWN] = "unknown",
		[HARDWARE_REVISION_TOPAZ_A] = "bbic4_rev_a0",
		[HARDWARE_REVISION_TOPAZ_B] = "bbic4_rev_a1",
		[HARDWARE_REVISION_TOPAZ_A2] = "bbic4_rev_a2",
	};

	/* Host board will not support hadware revision.*/
	if (hw_rev == HARDWARE_REVISION_UNKNOWN) {
		hw_rev = read_hardware_rev();

		if (hw_rev >= ARRAY_SIZE(hw_ver_descs))
			hw_rev = HARDWARE_REVISION_UNKNOWN;
	}

	seq_printf(m, "%s\n", hw_ver_descs[hw_rev]);

	return 0;
}

static int reboot_cause_proc_show(struct seq_file *m, void *v)
{
	unsigned int reboot_cause;

	reboot_cause = hw_info_get_reboot_cause();

	seq_printf(m, "%u\n", reboot_cause);

        return 0;
}

static int hw_rev_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hw_rev_proc_show, NULL);
}

static int reboot_cause_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, reboot_cause_proc_show, NULL);
}

static const struct file_operations hw_rev_proc_fops = {
	.open		= hw_rev_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations reboot_cause_proc_fops = {
	.open           = reboot_cause_proc_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int __init proc_hw_rev_init(void)
{
	proc_create("hw_revision", 0, NULL, &hw_rev_proc_fops);
	proc_create("reboot_cause", 0, NULL, &reboot_cause_proc_fops);
	return 0;
}
static void __exit proc_hw_rev_exit(void)
{
	remove_proc_entry("hw_revision", NULL);
	remove_proc_entry("reboot_cause", NULL);
}

module_init(proc_hw_rev_init);
module_exit(proc_hw_rev_exit);
