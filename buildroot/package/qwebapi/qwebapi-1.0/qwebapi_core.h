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

#ifndef _QWEBAPI_CORE_H_
#define _QWEBAPI_CORE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "qwebapi_json.h"
#include "qwebapi_debug.h"

/*****************************ENUM   DEFINITION*******************************/
typedef enum {
	QWEBAPI_TYPE_OBJECT = 0,
	QWEBAPI_TYPE_INT,
	QWEBAPI_TYPE_UINT,
	QWEBAPI_TYPE_UINT64,
	QWEBAPI_TYPE_STRING,
} data_type;

/*****************************STRUCT DEFINITION*******************************/
struct qwebitem {
	char *key;
	data_type type;
	int not_directly_set;

	int (*set_obj) (char *path, JSON * obj);
	union {
		int (*set_int) (char *path, int value);
		int (*set_uint) (char *path, unsigned int value);
		int (*set_string) (char *path, char *value);
	} set_func;
	int (*set_before) (char *path);
	int (*set_after) (char *path);

	JSON *(*get_obj) (char *path, int *perr);
	union {
		int (*get_int) (char *path, int *perr);
		unsigned int (*get_uint) (char *path, int *perr);
		 uint64_t(*get_uint64) (char *path, int *perr);
		char *(*get_string) (char *path, int *perr);
	} get_func;
	int (*get_before) (char *path);
	int (*get_after) (char *path);

	int (*add_func) (char *path, char *value);
	int (*del_func) (char *path);
	int (*get_size) (char *path);
	int (*check) (char *path, JSON * obj);
	int (*entry_exist) (char *path);
#ifdef TOPAZ_DBDC
	int (*apply_for_change) (char *path);
#endif

	struct qwebitem *child;
};

extern struct qwebitem *qwebapi_root;

#endif
