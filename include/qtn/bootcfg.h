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

/*
 *  Syscfg module - uses config sector for common filesytem between linux and
 *  uboot.
 */


typedef u32 bootcfg_t;

/******************************************************************************
	Function:   bootcfg_create
	Purpose:	create file
 	Returns:	0 if successful			
  	Note:  	    if size is zero, the proc entry is created but
  	            no data is allocated until the first write
 *****************************************************************************/
int bootcfg_create(const char *filename,u32 size);

/******************************************************************************
	Function:   bootcfg_delete
	Purpose:	delete file
 	Returns:	0 if successful			
  	Note:  	    
 *****************************************************************************/
int bootcfg_delete(const char *token);

/******************************************************************************
   Function:    bootcfg_get_var
   Purpose:     Get variable from environment
   Returns:     NULL if variable not found, pointer to storage otherwise
   Note:        variable value copied to storage
 *****************************************************************************/
char* bootcfg_get_var(const char *variable, char *storage);

/******************************************************************************
   Function:    bootcfg_set_var
   Purpose:     Set variable to environment
   Returns:     NULL if variable not found, pointer to storage otherwise
   Note:        variable value copied to storage
 *****************************************************************************/
int bootcfg_set_var(const char *var, const char *value);

