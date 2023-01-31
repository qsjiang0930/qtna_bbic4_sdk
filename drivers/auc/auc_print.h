/**
 * Copyright (c) 2009 - 2017 Quantenna Communications Inc
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

#ifndef __AUC_PRINT_H__
#define __AUC_PRINT_H__

#include <qtn/shared_print_buf.h>

extern unsigned (*uc_print_auc_cb)(struct shared_print_consumer* shared_buf, unsigned max_lines);

#endif /* __AUC_PRINT_H__ */
