/*SH1
 *******************************************************************************
 **                                                                           **
 **         Copyright (c) 2009 - 2018 Quantenna Communications, Inc.          **
 **                                                                           **
 **  File        : qtn_common.h                                               **
 **  Description :                                                            **
 **                                                                           **
 *******************************************************************************
 **  Copyright 1992-2014 The FreeBSD Project. All rights reserved.            **
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
 **  Alternatively, this software may also be distributed under the terms of  **
 **  the GNU General Public License ("GPL") version 2, or (at your option)    **
 **  any later version as published by the Free Software Foundation.          **
 **                                                                           **
 *******************************************************************************
 EH1
 */

#ifndef QTN_COMMON_H
#define QTN_COMMON_H

#ifdef CONFIG_QTNA_WIFI
#include "crypto/md5.h"
#include "common/defs.h"

#define QTN_MD5_STR_BUF_LEN	(MD5_MAC_LEN*2 + 1)

int qtn_util_md5_convert_passphrase(const string_64 psk_web, string_64 pre_shared_key);
#endif /* CONFIG_QTNA_WIFI */

#endif /* QTN_COMMON_H */
