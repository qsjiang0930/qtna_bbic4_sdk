/**
 * Copyright (c) 2011-2017 Quantenna Communications Inc
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

#include "qtn/qvsp.h"
#include "qvsp_nl.h"
#include "qvsp_private.h"

const struct qvsp_cfg_param qvsp_cfg_params[] = QVSP_CFG_PARAMS;

int qvsp_ioctl_cmd(struct qvsp_c *qvsp, enum qvsp_cfg_param_e param)
{
	if (qvsp && qvsp->ioctl && qvsp->ioctl_token) {
		return qvsp->ioctl(qvsp->ioctl_token, param, qvsp->cfg_param[param]);
	} else {
		return -EBADF;
	}
}

static void
_qvsp_disable(struct qvsp_c *qvsp)
{
	_MOD_DEC_USE(THIS_MODULE);

	pr_info("Disabling VSP\n");

	qvsp_inactive_flag_set(qvsp, QVSP_INACTIVE_CFG);
}

void qvsp_invoke_cfg_cb(struct qvsp_c *qvsp, uint32_t index, uint32_t value)
{
	if (index == QVSP_CFG_ENABLED) {
		if (value > 0) {
			if (qvsp_enable(qvsp) != 0) {
				return;
			}
		} else {
			_qvsp_disable(qvsp);
		}
	}
	qvsp->cfg_param[index] = value;

	qvsp_ioctl_cmd(qvsp, index);

	/* Send the config to QSTAs if in AP mode */
	if (!qvsp->stamode && qvsp->cb_cfg) {
		qvsp->cb_cfg(qvsp->ioctl_token, index, value);
	}
}

void qvsp_disable(struct qvsp_c *qvsp)
{
	if (!qvsp_inactive_flag_cleared(qvsp)) {
		return;
	}

	_qvsp_disable(qvsp);

	/* Do not need to forward cfg change request to server because
	 * the calling function creates its own server request.
	 */

	qvsp->cfg_param[QVSP_CFG_ENABLED] = 0;

	qvsp_ioctl_cmd(qvsp, QVSP_CFG_ENABLED);

	if (!qvsp->stamode && qvsp->cb_cfg) {
		qvsp->cb_cfg(qvsp->ioctl_token, QVSP_CFG_ENABLED, 0);
	}
}

int qvsp_enable(struct qvsp_c *qvsp)
{
	_MOD_INC_USE(THIS_MODULE, return 1);

	pr_info("Enabling VSP\n");

	qvsp_inactive_flag_clear(qvsp, QVSP_INACTIVE_CFG);

	return 0;
}

static int qvsp_ioctl_cfg_set(struct qvsp_c *qvsp, uint32_t index, uint32_t value)
{
/* Forward the request. Check parameters on server side. */
	qvsp_nl_cfg_set(qvsp, index, value);

	return 0;
}

/*
 * Process a command from other modules to change configuration
 */
void qvsp_cmd_vsp_cfg_set(struct qvsp_c *qvsp, uint32_t index, uint32_t value)
{
	qvsp_lock();
	qvsp_ioctl_cfg_set(qvsp, index, value);
	qvsp_unlock();
}
EXPORT_SYMBOL(qvsp_cmd_vsp_cfg_set);

/*
 * Process a command from other modules to return configuration
 */
int qvsp_cmd_vsp_cfg_get(struct qvsp_c *qvsp, uint32_t index, uint32_t *value)
{
	int ret = 0;

	qvsp_lock();

	if (index >= QVSP_CFG_MAX) {
		ret = -EINVAL;
	} else {
		*value = qvsp->cfg_param[index];
	}

	qvsp_unlock();

	return ret;
}
EXPORT_SYMBOL(qvsp_cmd_vsp_cfg_get);

void qvsp_cfg_init(struct qvsp_c *qvsp)
{
	const struct qvsp_cfg_param *param;
	int i;

	/* Generate a "duplicate case value" error if tables and enums are out of sync*/
	COMPILE_TIME_ASSERT(QVSP_CFG_MAX == ARRAY_SIZE(qvsp_cfg_params));
	COMPILE_TIME_ASSERT(QVSP_STRM_STATE_MAX <= 0xFF);  /* These enums are cast to char */

	for (i = 0; i < QVSP_CFG_MAX; i++) {
		param = &qvsp_cfg_params[i];
		qvsp->cfg_param[i] = param->default_val;
	}
}

