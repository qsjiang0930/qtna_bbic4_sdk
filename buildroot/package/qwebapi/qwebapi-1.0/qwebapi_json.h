/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2015 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : qwebapi_json.h                                             **
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
EH0*/
#ifndef __QWEBAPI_JSON_H
#define __QWEBAPI_JSON_H

#include <stdio.h>
#include <stdint.h>
#include <json/json.h>

#define JSON                                    json_object
#define JSON_STRING                             json_type_string

#define JSON_ADD_INT_FIELD(p, key, value)       (json_object_object_add((p), (key), json_object_new_int((value))))
#define JSON_ADD_DOUBLE_FIELD(p, key, value)    (json_object_object_add((p), (key), json_object_new_double((value))))
#define JSON_ADD_STRING_FIELD(p, key, value)    (json_object_object_add((p), (key), json_object_new_string((value))))
#define JSON_ADD_FIELD(p, key, value)           (json_object_object_add((p), (key), (value)))
#define JSON_ADD_ITEM(p, o)                     (json_object_array_add((p), (o)))
#define JSON_NEW_OBJ()                          (json_object_new_object())
#define JSON_NEW_ARRAY()                        (json_object_new_array())
#define JSON_NEW_INT(value)                     (json_object_new_int64((value)))
#define JSON_NEW_STRING(value)                  (json_object_new_string((value)))
#define JSON_GET_INT(p)                         (json_object_get_int((p)))
#define JSON_GET_DOUBLE(p)                      (json_object_get_double((p)))
#define JSON_GET_STRING(p)                      (json_object_get_string((p)))
#define JSON_GET_TYPE(p)                        (json_object_get_type((p)))
#define JSON_GET_REF(p)                         (json_object_get((p)))
#define JSON_PUT_REF(p)                         (json_object_put((p)))
#define JSON_GET_OBJ(p, key, o)                 (json_object_object_get_ex((p), (key), (o)))
#define JSON_GET_ITEM(p, idx)                   (json_object_array_get_idx((p), (idx)))
#define JSON_PARSE(string)                      (json_tokener_parse((string)))
#define JSON_TO_STRING(p)                       (json_object_to_json_string((p)))
#define JSON_FREE_STRING(string)
#define JSON_FOREACH(p, key, o)                 json_object_object_foreach((p), key, (o))

#endif
