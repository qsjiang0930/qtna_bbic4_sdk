/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qwebapi.c                                                  **
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

#define _GNU_SOURCE		/* See feature_test_macros(7) */
#include "qwebapi.h"
#include "qwebapi_core.h"
#include "qwebapi_util.h"

struct qwebapi_err_set {
	int err;
	const char *desc;
};

struct qwebapi_err_set qwebapi_errs[] = {
	{QWEBAPI_OK, "success"},
	{QWEBAPI_ERR_INVALID_PATH, "path error"},
	{QWEBAPI_ERR_INVALID_FORMAT, "JSON format error"},
	{QWEBAPI_ERR_INVALID_VALUE, "value error"},
	{QWEBAPI_ERR_NOT_AVALIABLE, "API not available"},
	{QWEBAPI_ERR_READONLY, "ReadOnly"},
	{QWEBAPI_ERR_NOT_DIRECTLY_SET, "Not allowed directly to set this item"},
	{QWEBAPI_ERR_NOT_SUPPORT, "Not Support"},

	{QWEBAPI_ERR_NOT_DEFINED, "error undefined"}
};

/* save the result of Get function */
static int is_get_success = 0;
extern struct qwebitem *qweb_root;

#define GET_NEXT(_item) ((((_item)+1)->key==NULL)?NULL:(_item+1))

static JSON *get_json_qweb_item(struct qwebitem *item, char *path, int index,
				int *perr);
static struct qwebitem *find_qwebitem(char *path, struct qwebitem *root,
				      int *pindex, int *perr);

static int set_json_obj_by_type(struct qwebitem *item, char *path, JSON * obj)
{
	int ret;

	if (item->set_before) {
		ret = item->set_before(path);
		if (ret)
			return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	if (item->check) {
		ret = item->check(path, obj);
		if (ret) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, path = %s, check failed \n",
				   __func__, __LINE__, path);
			return ret;
		}
	}

	if (item->set_obj) {
		ret = item->set_obj(path, obj);
	} else if ((item->type == QWEBAPI_TYPE_INT) && (item->set_func.set_int)) {
		ret = item->set_func.set_int(path, JSON_GET_INT(obj));
	} else if ((item->type == QWEBAPI_TYPE_UINT)
		   && (item->set_func.set_uint)) {
		ret = item->set_func.set_uint(path, JSON_GET_INT(obj));
	} else if ((item->type == QWEBAPI_TYPE_STRING)
		   && (item->set_func.set_string)) {
		ret =
		    item->set_func.set_string(path,
					      (char *)JSON_GET_STRING(obj));
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, path = %s, item->set is NULL", __func__,
			   __LINE__, path);
		ret = QWEBAPI_ERR_READONLY;
	}

	if (item->set_after) {
		ret = item->set_after(path);
		if (ret)
			return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	return ret;
}

static int set_json_qweb_item(struct qwebitem *item, char *path, int index,
			      JSON * obj)
{
	int ret = 0;		/* init ret as 0 */
	struct qwebitem *child;

	if ((index < 0) && (item->get_size)) {
		int i, n = item->get_size(path);
		for (i = 0; i < n; i++) {
			JSON *child_obj = JSON_GET_ITEM(obj, i);
			if (child_obj) {
				char *tpath;
				if (asprintf
				    (&tpath, "%s%s%d%s", path, ARR_START, i,
				     ARR_END) > 0) {
					ret =
					    set_json_qweb_item(item, tpath, i,
							       child_obj);
					safe_free(tpath);
				}
			}
		}
	} else {
		if ((child = item->child)) {
			while (child) {
				JSON *child_obj;
				JSON_GET_OBJ(obj, child->key, &child_obj);
				if (child_obj) {
					char *tpath;
					if (asprintf
					    (&tpath, "%s.%s", path,
					     child->key) > 0) {
						ret =
						    set_json_qweb_item(child,
								       tpath,
								       -1,
								       child_obj);
						safe_free(tpath);
					}
				}
				child = GET_NEXT(child);
			}
		} else
			ret = set_json_obj_by_type(item, path, obj);
	}
	return ret;
}

static JSON *get_json_obj_by_type(struct qwebitem *item, char *path, int *perr)
{
	int ret;
	JSON *obj = NULL;

	if (item->get_before) {
		ret = item->get_before(path);
		if (ret) {
			*perr = QWEBAPI_ERR_NOT_AVALIABLE;
			return NULL;
		}
	}

	if (item->get_obj)
		obj = item->get_obj(path, perr);
	else if ((item->type == QWEBAPI_TYPE_INT) && (item->get_func.get_int)) {
		obj = JSON_NEW_INT(item->get_func.get_int(path, perr));
	} else if ((item->type == QWEBAPI_TYPE_STRING)
		   && (item->get_func.get_string)) {
		obj = JSON_NEW_STRING(item->get_func.get_string(path, perr));
	} else if ((item->type == QWEBAPI_TYPE_UINT)
		   && (item->get_func.get_uint)) {
		obj = JSON_NEW_INT(item->get_func.get_uint(path, perr));
	} else if ((item->type == QWEBAPI_TYPE_UINT64)
		   && (item->get_func.get_uint64)) {
		obj = JSON_NEW_INT(item->get_func.get_uint64(path, perr));
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, path = %s, item->get is NULL", __func__,
			   __LINE__, path);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	}

	if (item->get_after) {
		ret = item->get_after(path);
		if (ret) {
			*perr = QWEBAPI_ERR_NOT_AVALIABLE;
			if (obj) {
				JSON_PUT_REF(obj);
			}
			return NULL;
		}
	}

	/* set get function return flag */
	if (*perr == 0)
		is_get_success = 1;

	return obj;
}

static JSON *get_json_qweb_item(struct qwebitem *item, char *path, int index,
				int *perr)
{
	struct qwebitem *child;
	JSON *obj = NULL;

	if ((index < 0) && (item->get_size)) {
		int i, n = item->get_size(path);
		obj = JSON_NEW_ARRAY();
		for (i = 0; i < n; i++) {
			char *tpath;
			if (asprintf
			    (&tpath, "%s%s%d%s", path, ARR_START, i,
			     ARR_END) > 0) {
				*perr = 0;
				if (item->entry_exist) {
					if (item->entry_exist(tpath) == 0) {
						JSON *null_array =
						    JSON_NEW_OBJ();
						JSON_ADD_ITEM(obj, null_array);
						continue;
					}
				}
				JSON *j =
				    get_json_qweb_item(item, tpath, i, perr);

				if (is_get_success)
					JSON_ADD_ITEM(obj, j);
				safe_free(tpath);
			}
		}
	} else {
		if ((child = item->child)) {
			obj = JSON_NEW_OBJ();
			if (item->entry_exist) {
				if (item->entry_exist(path) == 0)
					return obj;
			}
			while (child) {
				char *tpath;
				if (asprintf(&tpath, "%s.%s", path, child->key)
				    > 0) {
					*perr = 0;
					JSON *j =
					    get_json_qweb_item(child, tpath, -1,
							       perr);
					if (*perr == QWEBAPI_OK)
						JSON_ADD_FIELD(obj, child->key,
							       j);

					safe_free(tpath);
				}
				child = GET_NEXT(child);
			}
		} else
			obj = get_json_obj_by_type(item, path, perr);
	}
	return obj;
}

static int get_index(char **path, struct qwebitem *item)
{
	int index = -1;
	char *tmp = *path;
	if (*tmp != '\0') {
		if (item->get_size) {
			char *start, *end;
			start = strcasestr(tmp, ARR_START);
			end = strcasestr(tmp, ARR_END);

			if ((start == NULL) || (end == NULL)) {
				index = QWEBAPI_ERR_INVALID_PATH;
				goto bail;
			}
			index = atoi(start + strlen(ARR_START));
			tmp = end + 1;
		}

		if (*tmp != '\0')
			tmp++;
	}
	*path = tmp;
 bail:
	return index;
}

static struct qwebitem *find_qwebitem(char *path, struct qwebitem *root,
				      int *pindex, int *err)
{
	struct qwebitem *r = NULL;

	while (root) {
		if (strncmp(path, root->key, strlen(root->key)) == 0) {
			int index;
			path += strlen(root->key);
			index = get_index(&path, root);
			if (index >= -1) {
				if (*path == '\0') {
					r = root;
					*pindex = index;
				} else {
					r = find_qwebitem(path, root->child,
							  pindex, err);
				}
			} else {
				*err = index;
			}
			break;
		}
		root = GET_NEXT(root);
	}
	if (root == NULL)
		*err = QWEBAPI_ERR_INVALID_PATH;

	return r;
}

int qweb_set_obj(char *path, JSON * obj)
{
	int index;
	int perr = 0;
	struct qwebitem *item;

	if ((item = find_qwebitem(path, qweb_root, &index, &perr))) {
		if (!item->not_directly_set)
			perr = set_json_qweb_item(item, path, index, obj);
		else
			perr = QWEBAPI_ERR_NOT_DIRECTLY_SET;
	}
#ifdef TOPAZ_DBDC
	if (perr == QWEBAPI_OK && item && item->apply_for_change) {
		perr = item->apply_for_change(path);
	}
#endif
	return perr;
}

JSON *qweb_get_obj(char *path, int *perr)
{
	int index;
	JSON *obj = NULL;
	struct qwebitem *item;

	/* init variable:is_get_success */
	is_get_success = 0;

	if ((item = find_qwebitem(path, qweb_root, &index, perr))) {
		obj = get_json_qweb_item(item, path, index, perr);
	}

	/* return JSON value if some subnotes return OK */
	if (is_get_success == 1)
		*perr = 0;

	return obj;
}

static int add_json_qweb_item(struct qwebitem *item, char *path, int index,
			      JSON * obj)
{
	int ret = -1;

	if (index >= -1 && item->child) {
		if (item->add_func) {
			ret =
			    item->add_func(path, (char *)JSON_GET_STRING(obj));
		}
	}
	return ret;
}

int qweb_add_obj(char *path, JSON * obj)
{
	int index;
	int perr = 0;
	struct qwebitem *item = NULL;

	if ((item = find_qwebitem(path, qweb_root, &index, &perr))) {
		perr = add_json_qweb_item(item, path, index, obj);
	}
#ifdef TOPAZ_DBDC
	if (perr >= QWEBAPI_OK && item && item->apply_for_change) {
		int perr_apply = 0;
		perr_apply = item->apply_for_change(path);
		if(perr_apply < QWEBAPI_OK) {
			perr = perr_apply;
		}
	}
#endif
	return perr;
}

static int del_json_qweb_item(struct qwebitem *item, char *path, int index)
{
	int ret = -1;

	if (index >= 0 && item->child) {
		if (item->del_func) {
			ret = item->del_func(path);
		}
	}
	return ret;
}

int qweb_del_obj(char *path)
{
	int index;
	int perr = 0;
	struct qwebitem *item = NULL;

	if ((item = find_qwebitem(path, qweb_root, &index, &perr))) {
		perr = del_json_qweb_item(item, path, index);
	}
#ifdef TOPAZ_DBDC
	if (perr == QWEBAPI_OK && item && item->apply_for_change) {
		perr = item->apply_for_change(path);
	}
#endif
	return perr;
}

int qweb_get(char *path, char **value)
{
	char *str = NULL;
	int err = 0;
	JSON *obj;

	if ((obj = qweb_get_obj(path, &err))) {
		str = strdup(JSON_TO_STRING(obj));
		JSON_PUT_REF(obj);
	}

	*value = str;
	return err;
}

int qweb_set(char *path, char *value)
{
	int err;
	JSON *obj;

	obj = JSON_PARSE(value);
	if (obj == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is not a JSON format.\n", __func__,
			   __LINE__);
		return QWEBAPI_ERR_INVALID_FORMAT;
	}

	err = qweb_set_obj(path, obj);

	return err;
}

int qweb_add(char *path, char *value)
{
	int err;
	JSON *obj;

	obj = JSON_PARSE(value);

	if (obj == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is not a JSON format.\n", __func__,
			   __LINE__);
		return QWEBAPI_ERR_INVALID_FORMAT;
	}

	err = qweb_add_obj(path, obj);

	return err;
}

int qweb_del(char *path)
{
	int err = 0;

	err = qweb_del_obj(path);

	return err;
}

char *qweb_get_result(int err)
{
	JSON *obj;
	char *str;
	struct qwebapi_err_set *perr = qwebapi_errs;

	while (perr->err != QWEBAPI_ERR_NOT_DEFINED) {
		if (perr->err == err)
			break;
		perr++;
	}

	obj = JSON_NEW_OBJ();
	JSON_ADD_STRING_FIELD(obj, "result", perr->desc);

	str = strdup(JSON_TO_STRING(obj));
	JSON_PUT_REF(obj);

	return str;
}

int qweb_get_item_count(char *path, int *count)
{
	int index;
	int cnt = 0;
	struct qwebitem *child;
	struct qwebitem *item;
	int perr = QWEBAPI_OK;

	if ((item = find_qwebitem(path, qweb_root, &index, &perr))) {
		if ((child = item->child)) {
			while (child) {
				cnt++;
				child = GET_NEXT(child);
			}
		}
	}
	*count = cnt;

	return perr;
}

int qweb_get_item_size(char *path, int *size)
{
	int index;
	struct qwebitem *item;
	int perr = QWEBAPI_OK;

	if ((item = find_qwebitem(path, qweb_root, &index, &perr))) {
		if (item->get_size)
			*size = item->get_size(path);
		else
			*size = 1;
	}

	return perr;
}
