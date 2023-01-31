/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qweb.c                                                     **
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

#include "qwebapi.h"
#include "qwebapi_util.h"

int main(int argc, char **argv)
{

	int ret = -1;
	char *value;

	if (argc < 2) {
		goto bail;
	}

	if (strcmp(argv[1], "set") == 0
			|| strcmp(argv[1], "set_inactive") == 0
			|| strcmp(argv[1], "SetParameterValues") == 0) {
		if (argc < 4)
			goto bail;

		if (strcmp(argv[1], "set_inactive") == 0)
			qweb_set_inactive_mode(1);

		ret = qweb_set(argv[2], argv[3]);
		value = qweb_get_result(ret);
		printf("%s\n", value);
		safe_free(value);

	} else if (strcmp(argv[1], "get") == 0
		   || strcmp(argv[1], "get_inactive") == 0
		   || strcmp(argv[1], "GetParameterValues") == 0) {
		if (argc < 3)
			goto bail;

		if (strcmp(argv[1], "get_inactive") == 0)
			qweb_set_inactive_mode(1);

		ret = qweb_get(argv[2], &value);
		if (ret < 0) {
			value = qweb_get_result(ret);
		}
		printf("%s\n", value);
		safe_free(value);
	} else if (strcmp(argv[1], "addobj") == 0
		   || strcmp(argv[1], "AddObject") == 0) {
		if (argc < 4)
			goto bail;

		ret = qweb_add(argv[2], argv[3]);
		if(ret > 0) {
			printf("{\"index\":\"%d\"}\n", ret);
		}
		else {
			value = qweb_get_result(ret);
			printf("%s\n", value);
			safe_free(value);
		}
	} else if (strcmp(argv[1], "delobj") == 0
		   || strcmp(argv[1], "DeleteObject") == 0) {
		if (argc < 3)
			goto bail;

		ret = qweb_del(argv[2]);
		value = qweb_get_result(ret);
		printf("%s\n", value);
		safe_free(value);
	} else if (strcmp(argv[1], "get_count") == 0) {
		int count;
		if (argc < 3)
			goto bail;

		ret = qweb_get_item_count(argv[2], &count);
		if (ret < 0) {
			value = qweb_get_result(ret);
			printf("%s\n", value);
			safe_free(value);
		} else
			printf("%d\n", count);
	} else if (strcmp(argv[1], "get_size") == 0) {
		int count;
		if (argc < 3)
			goto bail;

		ret = qweb_get_item_size(argv[2], &count);
		if (ret < 0) {
			value = qweb_get_result(ret);
			printf("%s\n", value);
			safe_free(value);
		} else
			printf("%d\n", count);
	} else if (strcmp(argv[1], "clean_inactive") == 0) {
		qweb_clean_inactive_cfg();
		printf("success\n");
	} else

		goto bail;

	return ret;
 bail:
	printf("\
                help\n\
                set/SetParameterValues                //set config to WiFi Chip.\n\
                                                      //set path value \n\
                                                      //eg: set Device.WiFi.Radio.{0}.Channel { \"Channel\": 100 }\n\
                                                      //value must be JSON format string.\n\n\
                get/GetParameterValues                //get config from WiFi Chip.\n\
                                                      //eg:get Device.WiFi.Radio.{0}.Channel \n\
                                                      //get functions will return the string of JSON fromat.\n\
                addobj/AddObject                      //Add an object, you should input a radio name as parameter\n\
                                                      //eg: AddObject Device.WiFi.SSID.{2} \"wifi0\".\n\
                delobj/DeleteObject                   //Delete an object \n\
                                                      //eg: DeleteObject Device.WiFi.SSID.{2}\n");
	return ret;

}
