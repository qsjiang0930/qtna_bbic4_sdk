/*
 * (C) Copyright 2013 Quantenna Communications Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/io.h>

#include <qtn/qtn_debug.h>
#include <common/topaz_platform.h>

#define PROC_NAME "temp_sens"
#define TOPAZ_TEMP_SENS_DRIVER_NAME		"topaz_tempsens"

#define TOPAZ_TEMPSENS_INIT_VAL	-40
#define TOPAZ_TEMPSENS_CODE_TBL_SIZE 34
#define TOPAZ_TEMPSENS_STEP 5 /*Each point on the table corresponds to 5 Degree C step */

/* Temperature curve is non-linear, this is a table of values reported by the temperature sensor for a range from -40 to 130 C for increments of 5 C*/
const int code_idx[TOPAZ_TEMPSENS_CODE_TBL_SIZE] = {3800, 3792, 3783, 3774, 3765, 3756, 3747, 3737, 3728, 3718, 3708, 3698, 3688, 3678, 3667, 3656, 3645,
	                    3634, 3623, 3611, 3600, 3588, 3575, 3563, 3550, 3537, 3524, 3510, 3496, 3482, 3467, 3452, 3437, 3421};

static int64_t coeffA = 0;
static int64_t coeffB = 0;
static int64_t coeffC = 0;
static int pivot;

static int64_t topaz_temp_3x3_determinate(int64_t m0[], int64_t m1[], int64_t m2[])
{
	return   (m0[0] * (m1[1]*m2[2] - m2[1]*m1[2]))
	       - (m1[0] * (m0[1]*m2[2] - m2[1]*m0[2]))
	       + (m2[0] * (m0[1]*m1[2] - m1[1]*m0[2]));
}


/*
 * all these complex calculations are performed only once at init time only, to
 * curve-fit the above lookup table. Because this is calculated (once) at run-time init,
 * it allows for the fact that the lookup table may be modified in the future
 */
static int topaz_temp_quadratic_fit(void)
{
	int64_t a[3] = {0, 0, 0};
	int64_t b[3] = {0, 0, 0};
	int64_t c[3] = {0, 0, 0};
	int64_t d[3] = {0, 0, 0};
	int64_t D;
	int index;
#ifdef CONFIG_ARCH_ARC_CURR_IN_REG
	unsigned long flags;
#endif

	/* re-scale values to minimise numerical dynamic range */
	pivot = (code_idx[0] + code_idx[TOPAZ_TEMPSENS_CODE_TBL_SIZE - 1]) / 2;

	/*
	 * do a fit by assuming quadratic form, and create independent equations
	 * by summing over the data set using arbitrary mathematical operations;
	 * this is a type of least-squares fitting
	 */
	for (index = 0; index < TOPAZ_TEMPSENS_CODE_TBL_SIZE; index++) {
		int64_t temp = TOPAZ_TEMPSENS_INIT_VAL + (index * TOPAZ_TEMPSENS_STEP);
		int64_t value = code_idx[index] - pivot;

		a[0] += value * value;
		a[1] += value * value * temp;
		a[2] += value * value * temp * temp;
		b[0] += value;
		b[1] += value * temp;
		b[2] += value * temp * temp;
		c[1] += temp;
		c[2] += temp * temp;
		d[2] += temp * temp * temp;
	}

	c[0] = TOPAZ_TEMPSENS_CODE_TBL_SIZE;
	d[0] = c[1];
	d[1] = c[2];

	/* using Cramer's rule */
	D = topaz_temp_3x3_determinate(a, b, c);

	/* scale for precision */
	D +=  1 << 23;
	D >>= 24;

	if (D == 0) {
		return -1;
	}

	coeffA = topaz_temp_3x3_determinate(d, b, c);
	coeffB = topaz_temp_3x3_determinate(a, d, c);
	coeffC = topaz_temp_3x3_determinate(a, b, d);

#ifdef CONFIG_ARCH_ARC_CURR_IN_REG
	/*
	 * FIXME
	 * ARC may use r25 to store "current", while __divdi3 may use r25 for its
	 * own purposes and restores it at the end of function. Let's suppose a case that
	 * one ISR interrupts __divdi3 and performs an action of reading r25, a garbage value
	 * may be returned and that action(e.g. get_current()) may cause CPU hang.
	 */
	local_irq_save(flags);
#endif
	coeffA = (coeffA + (D >> 1)) / D;
	coeffB = (coeffB + (D >> 1)) / D;
	coeffC = (coeffC + (D >> 1)) / D;
#ifdef CONFIG_ARCH_ARC_CURR_IN_REG
	local_irq_restore(flags);
#endif

	return 0;
}


int topaz_read_internal_temp_sens(int *temp_intvl)
{
	int temp;
	int idx = 0;
	*temp_intvl = TOPAZ_TEMPSENS_INIT_VAL;

	temp = (readl(TOPAZ_SYS_CTL_TEMP_SENS_DATA) & TOPAZ_SYS_CTL_TEMP_SENS_DATA_TEMP);

	for (idx = 0; idx < TOPAZ_TEMPSENS_CODE_TBL_SIZE; idx++) {
		if (temp >= code_idx[idx]) {
			*temp_intvl = *temp_intvl + (idx * TOPAZ_TEMPSENS_STEP);
			break;
		}
	}
	return idx;
}
EXPORT_SYMBOL(topaz_read_internal_temp_sens);


/* returns temperature (in degrees C x2) using quadratic interpolation */
int topaz_read_internal_temp_sens_fine(void)
{
	int64_t prediction;
	int value;

	value = (readl(TOPAZ_SYS_CTL_TEMP_SENS_DATA) & TOPAZ_SYS_CTL_TEMP_SENS_DATA_TEMP);
	value -= pivot;

	/* basic quadratic equation */
	prediction = coeffA * value * value + coeffB * value + coeffC;

	/* this scaling calculates in integer half degree units (so divide by 2 for true result) */
	prediction +=  1 << 22;
	prediction >>= 23;

	return (int)prediction;
}
EXPORT_SYMBOL(topaz_read_internal_temp_sens_fine);


static int topaz_temp_sens_read_proc(char *page, char **start, off_t offset,
		int count, int *eof, void *_unused)
{
	const unsigned int lim = PAGE_SIZE - 1;
	int len = 0;
	int t;

	if (offset > 0) {
		*eof = 1;
		return 0;
	}

	t = topaz_read_internal_temp_sens_fine();

	len += snprintf(&page[len], lim-len, "Temperature is %d.%s C (+/- %u.%s C)\n", t >> 1,
		t % 2 ? "5" : "0", TOPAZ_TEMPSENS_STEP >> 1,
		TOPAZ_TEMPSENS_STEP % 2 ? "5" : "0");

	return len;
}

static int __init topaz_temp_sens_create_proc(void)
{
	struct proc_dir_entry *entry = create_proc_entry(PROC_NAME, 0600, NULL);
	if (!entry) {
		return -ENOMEM;
	}

	entry->write_proc = NULL;
	entry->read_proc = topaz_temp_sens_read_proc;

	return 0;
}

int __init topaz_temp_sens_init(void)
{
	int rc;

	rc = topaz_temp_sens_create_proc();
	if (rc) {
		return rc;
	}

	writel(TOPAZ_SYS_CTL_TEMPSENS_CTL_SHUTDWN, TOPAZ_SYS_CTL_TEMPSENS_CTL);
	writel(~(TOPAZ_SYS_CTL_TEMPSENS_CTL_START_CONV), TOPAZ_SYS_CTL_TEMPSENS_CTL);
	writel(TOPAZ_SYS_CTL_TEMPSENS_CTL_START_CONV, TOPAZ_SYS_CTL_TEMPSENS_CTL);

	rc = topaz_temp_quadratic_fit();

	if (rc) {
		printk(KERN_DEBUG "%s fail\n", __FUNCTION__);
		return rc;
	}

	printk(KERN_DEBUG "%s success\n", __FUNCTION__);
	return 0;
}

static void __exit topaz_temp_sens_exit(void)
{
	remove_proc_entry(PROC_NAME, NULL);
}

module_init(topaz_temp_sens_init);
module_exit(topaz_temp_sens_exit);

MODULE_DESCRIPTION("Topaz Temperature Sensor");
MODULE_AUTHOR("Quantenna");
MODULE_LICENSE("GPL");
