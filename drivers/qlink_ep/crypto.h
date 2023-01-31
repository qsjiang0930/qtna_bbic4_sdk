/**
 * Copyright (c) 2019 Quantenna Communications, Inc.
 * All rights reserved.
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
 **/

#ifndef _QLINK_EP_CRYPTO_H_
#define _QLINK_EP_CRYPTO_H_

#include "qlink_priv.h"

int qlink_mgmt_bip_is_valid(struct qlink_bss *bss, const u8 *data, size_t len);

#endif /* _QLINK_EP_CRYPTO_H_ */
