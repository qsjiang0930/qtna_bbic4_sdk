/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qwebapi.h                                                  **
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
EH1*/

#ifndef __QWEBAPI_H__
#define __QWEBAPI_H__

enum {
	QWEBAPI_ERR_NOT_DEFINED = -1,

	QWEBAPI_OK = 0,
	QWEBAPI_ERR_INVALID_PATH = -2,
	QWEBAPI_ERR_INVALID_FORMAT = -3,
	QWEBAPI_ERR_INVALID_VALUE = -4,
	QWEBAPI_ERR_NOT_AVALIABLE = -5,
	QWEBAPI_ERR_READONLY = -6,
	QWEBAPI_ERR_NOT_DIRECTLY_SET = -7,
	QWEBAPI_ERR_NOT_SUPPORT = -8,

} QWEBAPI_ERROR_CODE;

int qweb_get(char *path, char **value);
int qweb_set(char *path, char *value);
int qweb_add(char *path, char *value);
int qweb_del(char *path);

/**
 * * @brief Get the result which is a string of operate function.
 * *
 * * This API call is used to get the result of operate function.
 * *
 * * \param err:it is a IN param. it means the error code which
 * *            was returned by operate function.
 * *
 * * \return string result correspond to param err.
 * *
 * */
char *qweb_get_result(int err);

/**
 * * @brief Get the count of item.
 * *
 * * This API call is used to get the count of item in the array of TR181.
 * *
 * * \param path:it means the path of TR181, and this param is a string.
 * * \param count:it is a OUT param. it means the count of item.
 * *
 * * \return = 0 on success, < 0 on error, it correspond to QWEBAPI_ERROR_CODE.
 * *
 * * Unless an error occurs, the output will be 0.
 * */
int qweb_get_item_count(char *path, int *count);

/**
 * * @brief Get the size of item.
 * *
 * * This API call is used to get the size of item in the array of TR181.
 * *
 * * \param path:it means the path of TR181, and this param is a string.
 * * \param size:it is a OUT param. it means the size of array.
 * *
 * * \return = 0 on success, < 0 on error, it correspond to QWEBAPI_ERROR_CODE.
 * * if the path isn't an array, this size will be set 1.
 * *
 * * Unless an error occurs, the output will be 0.
 * */
int qweb_get_item_size(char *path, int *size);

/**
 * * @brief Set defer mode (For DBDC 2.4G only).
 * *
 * * After defer mode is enabled, the configuration will not be taken
 * * effect immediately.
 * * Disable defer mode and call qweb_apply_for_change(NULL) to take
 * * effect the deferred configuration.
 * *
 * * \enable = 0: disable defer mode, it is the default mode.
 * * \enable = 1: enable defer mode.
 * */
void qweb_set_defer_mode(int enable);

/**
 * * @brief get defer mode (For DBDC 2.4G only).
 * *
 * * \return = 0 on defer mode is disabled, = 1 on defer mode is enabled.
 * */
int qweb_get_defer_mode(void);

/**
 * * @brief Set inactive mode.
 * *
 * * After inactive mode is enabled, the object of next set/get operation
 * * will not be real system but files under /tmp/.qwebcfg/ directory.
 * *
 * * \enable = 0: disable inactive mode, it is the default mode.
 * * \enable = 1: enable inactive mode.
 * */
void qweb_set_inactive_mode(int enable);

/**
 * * @brief get inactive mode.
 * *
 * * \return = 0 on inactive mode is disabled, = 1 on inactive mode is enabled.
 * */
int qweb_get_inactive_mode(void);
#endif
