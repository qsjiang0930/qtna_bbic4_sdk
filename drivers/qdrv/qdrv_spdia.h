/**
  Copyright (c) 2018 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

 **/

#ifndef _QDRV_SPDIA_H_
#define _QDRV_SPDIA_H_

#include "qdrv_wlan.h"
#include <qtn/qspdia_proto.h>

void qdrv_spdia_dsp_finished(void);

uint32_t qdrv_spdia_get_buf(void **buf, uint16_t ioctl_bucket);

int qdrv_spdia_setup(void);

int qdrv_spdia_init(struct qdrv_wlan *qw);
int qdrv_spdia_exit(struct qdrv_wlan *qw);


#endif /* _QDRV_SPDIA_H_ */
