/**
  Copyright (c) 2011 - 2017 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <qtn/qtn_debug.h>

unsigned int g_dbg_log_module = 0;
unsigned int g_dbg_log_level[DBG_LM_MAX] = {DBG_LL_WARNING};
unsigned int g_dbg_log_func[DBG_LM_MAX] = {0};

MODULE_DESCRIPTION("Quantenna Debugging");
MODULE_AUTHOR("Quantenna Communications, Inc.");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

EXPORT_SYMBOL(g_dbg_log_module);
EXPORT_SYMBOL(g_dbg_log_level);
EXPORT_SYMBOL(g_dbg_log_func);
