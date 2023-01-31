/*
 * Copyright (c) 2008-2014 Quantenna Communications, Inc.
 * All rights reserved.
 *
 * Create a wrapper around other bootcfg datastores which compresses on write
 * and decompresses on read.
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
 * Syscfg module - uses config sector for common filesytem between linux and uboot.
 */

#include "bootcfg_drv.h"

#include <qtn/bootcfg.h>
#include <qtn/shared_defs_common.h>
#include <common/ruby_partitions.h>
#include <common/ruby_version.h>
#include <common/ruby_board_cfg.h>

#include <linux/crc32.h>
#include <linux/delay.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>	/* for copy_from_user */
#include <asm/board/board_config.h>

///////////////////////////////////////////////////////////////////////////////
//             Definitions
///////////////////////////////////////////////////////////////////////////////
#define DRV_NAME		"bootcfg"
#define DRV_VERSION		"1.1"
#define DRV_AUTHOR		"Quantenna Communciations, Inc."
#define DRV_DESC		"Boot Configuration Driver"

#define QTN_HW_BOARD_CFG_BIN	"qtn_hw_board_config.bin"

static struct proc_dir_entry *bootcfg_proc;
static struct proc_dir_entry *boardparam_proc;
static struct proc_dir_entry *bootcfg_dir;
static struct proc_dir_entry *pending_proc;

///////////////////////////////////////////////////////////////////////////////
//          Structures and types
///////////////////////////////////////////////////////////////////////////////
typedef struct sBootCfg {
	char entry[256];
	u32 addr;
	u32 len;
	int flags;
	struct proc_dir_entry *proc;
	struct sBootCfg *next;
} tsBootCfgFile, *ptsBootCfgFile;

typedef struct sBootCfgData {
	u32 crc;
	u8 data[BOOT_CFG_DATA_SIZE];
	int isValid;
	int dirty;
	int size;
} tsBootCfgData, *ptsBootCfgData;

///////////////////////////////////////////////////////////////////////////////
//          Global Data
///////////////////////////////////////////////////////////////////////////////
static tsBootCfgData gBootCfgData = { 0 };

static spinlock_t gBootCfgLock;

static ptsBootCfgFile gFiles = NULL;

static ptsBootCfgFile bootcfg_mount(const char *filename, u32 addr, u32 len);
static int bootcfg_defragment_locked(void);

// do flash ops in background
//static void bootcfg_do_flash(unsigned long data);
//struct tasklet_struct work = { 0, 0, ATOMIC_INIT(0), bootcfg_do_flash, 0};

static void bootcfg_store_write_wq(struct work_struct *unused);
static DECLARE_DELAYED_WORK(work, bootcfg_store_write_wq);

static int bootcfg_get_all_hw_board_config(char *buffer);

///////////////////////////////////////////////////////////////////////////////
//          Functions
///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
   Function:    bootcfg_crc32
   Purpose:     calculate crc for bootcfg area
   Returns:
   Note:
 *****************************************************************************/
static u32 bootcfg_crc32(u32 crc, const u8 * buf, u32 len)
{
	return crc32(crc ^ 0xffffffffL, buf, len) ^ 0xffffffffL;
}

#define BOOTCFG_COMMIT_DELAY_MS		500

/******************************************************************************
   Function:    bootcfg_store_write
   Purpose:     Writes data to flash device
   Returns:
   Note:        We now do this in deferred mode
	Should be called with gBootCfgLock
 *****************************************************************************/
static void bootcfg_store_write(void)
{
	WARN_ON(in_interrupt());

	/* keep pushing the commit into the future while updates are arriving */
	cancel_delayed_work_sync(&work);

	gBootCfgData.dirty = 1;

	schedule_delayed_work(&work, msecs_to_jiffies(BOOTCFG_COMMIT_DELAY_MS));
}

static void bootcfg_store_write_unsafe(void)
{
	WARN_ON(in_interrupt());

	/* keep pushing the commit into the future while updates are arriving */
	cancel_delayed_work_sync(&work);

	gBootCfgData.dirty = 1;

	schedule_delayed_work(&work, msecs_to_jiffies(BOOTCFG_COMMIT_DELAY_MS));
}

static struct bootcfg_store_ops *store_ops = NULL;

static void bootcfg_store_write_wq(struct work_struct *unused)
{
	int ret;
	ptsBootCfgData data = NULL;
	ptsBootCfgData reread_verify_data = NULL;
	size_t crc_size;
	size_t write_size;

	data = kmalloc(sizeof(gBootCfgData), GFP_KERNEL);
	reread_verify_data = kmalloc(sizeof(gBootCfgData), GFP_KERNEL);
	if (data == NULL || reread_verify_data == NULL) {
		printk(KERN_ERR "%s out of memory\n", __FUNCTION__);
		goto exit;
	}

	spin_lock(&gBootCfgLock);

	crc_size = gBootCfgData.size;
	write_size = gBootCfgData.size + sizeof(u32);
	memcpy(data->data, gBootCfgData.data, crc_size);

	data->crc = bootcfg_crc32(0, gBootCfgData.data, crc_size);
	/*
	 * TBD: leaving this flag set in the event of a failure will cause subsequent callers to
	 * hang.  A failure indication should be returned to the caller.
	 */
	gBootCfgData.dirty = 0;
	spin_unlock(&gBootCfgLock);

	ret = store_ops->write(store_ops, data, write_size);
	if (ret < 0) {
		printk(KERN_ERR "%s %s data write failed: %d\n",
				DRV_NAME, __FUNCTION__, ret);
		goto exit;
	}

	ret = store_ops->read(store_ops, reread_verify_data, write_size);
	if (ret < 0) {
		printk(KERN_ERR "%s %s data read for verify failed: %d\n",
				DRV_NAME, __FUNCTION__, ret);
		goto exit;
	}

	if (memcmp(data, reread_verify_data, write_size) != 0) {
		printk(KERN_ERR "%s %s data write verify failed\n",
				DRV_NAME, __FUNCTION__);
		goto exit;
	}

exit:
	kfree(data);
	kfree(reread_verify_data);
}

/******************************************************************************
   Function:    bootcfg_store_read
   Purpose:     reads data from flash, checks crc and sets valid bit
   Returns:
   Note:        todo: unmap on exit
	Should be called while gBootCfgLock is held
 *****************************************************************************/

static int empty_flash = 0;
module_param(empty_flash, int, 0);
#define VERSION_STR_SIZE 16

static int bootcfg_store_read(void)
{
	int ret;
	u32 crc;
	int32_t idx = 0;
	uint32_t env_size[] = {gBootCfgData.size, F64K_ENV_PARTITION_SIZE - sizeof(u32),
				BOOT_CFG_BASE_SIZE - sizeof(u32)};

	ret = store_ops->read(store_ops, &gBootCfgData, gBootCfgData.size + sizeof(u32));
	if (ret < 0 && ret != -ENODATA) {
		printk(KERN_ERR "%s %s data read failed: %d\n",
				DRV_NAME, __FUNCTION__, ret);
	} else {
		/* Check CRC */
		do {
			crc = bootcfg_crc32(0, gBootCfgData.data, env_size[idx]);
			if (crc == gBootCfgData.crc) {
				gBootCfgData.size = env_size[idx];
				break;
			}
		} while (++idx < ARRAY_SIZE(env_size));

		if (crc != gBootCfgData.crc) {
			printk(KERN_WARNING "%s %s: crc32 does not match crc: %x expect %x\n",
				DRV_NAME, __FUNCTION__, crc, gBootCfgData.crc);
		}

		if (empty_flash) {
			/*
			 * Empty out data. This may be due to corruption,
			 * decompression failure when eeprom is uninitialised,
			 * or a legitimately empty flash... user can override.
			 */
			ret = 0;
			memset(&gBootCfgData, 0, BOOT_CFG_SIZE);
		}
	}

	return ret;
}

static int __init bootcfg_store_init(void)
{
	int ret;
	size_t store_limit = 0;

	store_ops = bootcfg_get_datastore();
	if (store_ops == NULL) {
		printk(KERN_ERR "%s: no datastore provided\n", __FUNCTION__);
		return -ENODEV;
	}

	ret = store_ops->init(store_ops, &store_limit);
	if (ret) {
		printk(KERN_ERR "%s: datastore init failed for store, ret = %d\n",
				__FUNCTION__, ret);
		return ret;
	}

	if (store_limit) {
		/* a restricted number of bytes for storage is available */
		gBootCfgData.size = store_limit - sizeof(u32);
	} else {
		gBootCfgData.size = BOOT_CFG_DATA_SIZE;
	}

	if (gBootCfgData.size > BOOT_CFG_DATA_SIZE) {
		gBootCfgData.size = BOOT_CFG_DATA_SIZE;
	}

	return 0;
}

static void bootcfg_store_exit(void)
{
	if (store_ops && store_ops->exit)
		store_ops->exit(store_ops);
}

/*
 * Function:    bootcfg_find_var
 * Purpose:     Find the particular environment variable
 * Returns: ptr to the variable or NULL if it is not found
 * Note: It should be called within spin_lock/spin_unlock block.
 */
static char* bootcfg_find_var(char *ptr, const char *var)
{
	char *temp_ptr;
	u32 cmp_len;

	while (*ptr) {
		if ((temp_ptr = strchr(ptr, '=')) == NULL) {
			printk("Corrupted variable(s).\n");
			return NULL;
		}
		cmp_len = MAX(strlen(var), (temp_ptr - ptr));
		if (strncmp(var, ptr, cmp_len) == 0)
			return ptr;

		// flush to 0, end marked by double 0
		while (*ptr++) {
		}
	}
	return NULL;
}

/******************************************************************************
   Function:    bootcfg_get_var_locked
   Purpose:     Get variable from environment
   Returns:     NULL if variable not found, pointer to storage otherwise
   Note:        variable value copied to storage
 *****************************************************************************/
char *bootcfg_get_var_locked(const char *variable, char *storage)
{
	char *ptr;
	int len = strlen(variable);

	if (!len) {
		return NULL;
	}
	// printk("find %s %d\n",variable,len);

	ptr = (char *)gBootCfgData.data;
	while (*ptr) {
		if (strncmp(variable, ptr, len) == 0) {
			// found it, copy and return string
			strcpy(storage, &ptr[len]);
			return storage;
		}
		// flush to 0, end marked by double 0
		while (*ptr++) {
		}
	}
	return NULL;
}

char *bootcfg_get_var(const char *variable, char *storage)
{
	char *rv;

	spin_lock(&gBootCfgLock);
	rv = bootcfg_get_var_locked(variable, storage);
	spin_unlock(&gBootCfgLock);
	return rv;
}
EXPORT_SYMBOL(bootcfg_get_var);

/******************************************************************************
   Function:    bootcfg_set_var_locked
   Purpose:     Set variable to environment
   Returns:     NULL if variable not found, pointer to storage otherwise
   Note:        variable value copied to storage
 *****************************************************************************/
int bootcfg_set_var_locked(const char *var, const char *value)
{
	u32 var_len = strlen(var);
	char *ptr, *next;

	if (!var_len) {
		return -1;
	}

	// find the index
	ptr = (char *)gBootCfgData.data;
	ptr = bootcfg_find_var(ptr, var);
	if (ptr) {
		// found it, delete the entry
		next = ptr;

		// flush to next entry
		while (*next != 0) {
			next++;
		}

		// Now next points to /0. Copy the rest of the table
		while (*next || *(next + 1)) {
			next++;
			*ptr = *next;
			ptr++;
		}
		*ptr = 0; // mark end with double 0
	}

	// if we are deleting we are done, otherwise write the new value
	if (value != NULL) {

		ptr = (char *)gBootCfgData.data;
		while (*ptr) {
			// flush to end
			while (*ptr++) {
			}
		}
		while (*var) {
			*ptr++ = *var++;
		}

		*ptr++ = '=';
		while (*value) {
			*ptr++ = *value++;
		}
		*ptr++ = 0;	// mark end with double 0
		*ptr = 0;	// mark end with double 0
	}
	// dump for debug
#if 0
	ptr = (char *)(gBootCfgData.data);
	while (*ptr) {
		printk("%s\n", ptr);
		while (*ptr++) {
		}
	}
#endif
	return 0;
}


int bootcfg_set_var(const char *var, const char *value)
{
	int rv;

	spin_lock(&gBootCfgLock);
	rv = bootcfg_set_var_locked(var, value);
	spin_unlock(&gBootCfgLock);
	return rv;
}
EXPORT_SYMBOL(bootcfg_set_var);

/******************************************************************************
	Function:   bootcfg_get_end
	Purpose:	Get end of data section
	Returns:	0 if successful
	Note:	if size is zero, the proc entry is created but
		no data is allocated until the first write
		should be called while gBootCfgLock is held
 *****************************************************************************/
static u32 bootcfg_get_end(void)
{
	char tmpBuf[256];
	char *dataend;
	u32 addr;

	dataend = bootcfg_get_var_locked("config_data_end", tmpBuf);
	if (dataend == NULL) {
		printk("bootcfg: first entry in system\n");
		addr = BOOT_CFG_DEF_START;
	} else {
		if (sscanf(dataend, "=0x%x", &addr) != 1) {
			return 0;
		}
	}
	return addr;
}

/******************************************************************************
	Function:   bootcfg_delete
	Purpose:	delete file
	Returns:	0 if successful
	Note:
 *****************************************************************************/
int bootcfg_delete_locked(const char *token)
{
	char tmpBuf[256];
	ptsBootCfgFile prev = NULL;
	ptsBootCfgFile next;

	// figure out our address and len
	if (bootcfg_get_var_locked(token, tmpBuf) == NULL) {
		printk("bootcfg error: %s filename not found\n", token);
		return -1;
	}
	bootcfg_set_var_locked(token, NULL);

	/*
	 * unmount the file
	 */
	next = gFiles;
	while (next != NULL) {
		if (strcmp(next->entry, token) == 0) {
			remove_proc_entry(next->entry, bootcfg_dir);

			// fix links
			if (prev == NULL) {
				gFiles = next->next;
			} else {
				prev->next = next->next;
			}
			kfree(next);
			break;
		}
		prev = next;
		next = next->next;
		// error check for null here without finding entry?
	}

	/* defragment before releasing lock */
	bootcfg_defragment_locked();
	bootcfg_store_write();
	return 0;
}

int bootcfg_delete(const char *token)
{
	int rv;

	spin_lock(&gBootCfgLock);
	rv = bootcfg_delete_locked(token);
	spin_unlock(&gBootCfgLock);
	return rv;
}
EXPORT_SYMBOL(bootcfg_delete);

/******************************************************************************
	Function:   bootcfg_create_locked
	Purpose:	create file
	Returns:	0 if successful
	Note:	if size is zero, the proc entry is created but
		no data is allocated until the first write
 *****************************************************************************/
int bootcfg_create_locked(const char *filename, u32 size)
{
	char tmpBuf[256];
	u32 addr = 0;
	ptsBootCfgFile ptr, next;
	//printk("create %s %x\n",filename,size);
	if (bootcfg_get_var_locked(filename, tmpBuf) != NULL) {
		printk("bootcfg error: %s filename already taken\n", filename);
		spin_unlock(&gBootCfgLock);
		return -EFAULT;
	}

	if (size != 0) {
		// need exclusive access now so nobody messes up our allocation process
		if ((addr = bootcfg_get_end()) == 0) {
			printk("bootcfg error - getting cfg address\n");
			return -EFAULT;
		}
		// create our entry
		if ((size + addr) > gBootCfgData.size) {
			printk("bootcfg error - len out of range\n");
			return -EFAULT;
		}
		// set end marker
		sprintf(tmpBuf, "0x%08x", addr + size);
		bootcfg_set_var_locked("config_data_end", tmpBuf);
	}

	sprintf(tmpBuf, "cfg 0x%08x 0x%08x", addr, size);
	bootcfg_set_var_locked(filename, tmpBuf);

	// make it so - someone else could come in here, but the
	// flash data structure is intact, so should be ok
	bootcfg_store_write();
	ptr = bootcfg_mount(filename, addr, size);

	// add our file into list
	if (gFiles == NULL) {
		gFiles = ptr;
	} else {
		next = gFiles;
		while (next->next != NULL) {
			next = next->next;
		}
		next->next = ptr;
	}

	return 0;
}

int bootcfg_create(const char *filename, u32 size)
{
	int rv;

	spin_lock(&gBootCfgLock);
	rv = bootcfg_create_locked(filename, size);
	spin_unlock(&gBootCfgLock);
	return rv;
}
EXPORT_SYMBOL(bootcfg_create);

static inline u8 *bootcfg_get_first_cfg_addr(void)
{
	return gBootCfgData.data - offsetof(tsBootCfgData, data) + BOOT_CFG_DEF_START;
}

/*
 * Should be called with gBootCfgLock held
 */
static int bootcfg_set_var_probe(const char *var, const char *value)
{
	char *old_value_ptr = NULL;
	u32 old_value_len = 0;
	u32 size = strlen(var);
	char *ptr, *temp_ptr;

	if (!size)
		return 0;

	if (!value)
		return 1; /* variable will be deleted in bootcfg_set_var(). */

	size += strlen(value) + 1; /*+ '='*/
	size += 2; /* double \0 (end) */

	ptr = (char *)gBootCfgData.data;
	temp_ptr = bootcfg_find_var(ptr, var);
	if (temp_ptr) {
		old_value_ptr = strchr(temp_ptr, '=') + 1;
		old_value_len = strlen(old_value_ptr);
	}

	/* variable not found, let us check if it can be added to the end. */
	while (*ptr) {
		/* flush to end, end marked by double 0 */
		while (*ptr++)
			;
	}

	if ((ptr + size - old_value_len) < (char *)bootcfg_get_first_cfg_addr())
		return 1;

	printk("bootcfg error: Not enough space to store the %s variable.\n",
		temp_ptr ? "existing" : "new");
	return 0;
}

/******************************************************************************
	Function:   bootcfg_proc_write_env
	Purpose:	write data to boot environment
 	Returns:	Number of bytes written
  	Note:
 *****************************************************************************/
static int
bootcfg_proc_write_env(struct file *file, const char *buffer,
		       unsigned long count, void *data)
{
	/* get buffer size */
	char *procfs_buffer;
	char tmpBuf[256];
	char *ptr, *token, *arg;
	u32 len;

	if ((procfs_buffer = kmalloc(count + 1, GFP_KERNEL)) == NULL) {
		printk("bootcfg error: out of memory\n");
		return -ENOMEM;
	}

	/* write data to the buffer */
	if (copy_from_user(procfs_buffer, buffer, count)) {
		goto out;
	}

	spin_lock(&gBootCfgLock);

	ptr = (char *)procfs_buffer;
	ptr[count] = '\0';
	token = strsep(&ptr, " \n");

	// create a new file
	if (strcmp(token, "create") == 0) {
		// figure out our address and len
		token = strsep(&ptr, " ");
		if (bootcfg_get_var_locked(token, tmpBuf) != NULL) {
			printk("bootcfg error: %s filename already taken\n",
			       token);
			goto out_unlock;
		}
		arg = strsep(&ptr, " \n");
		if (arg == NULL) {
			printk("bootcfg error: must supply max size\n");
			goto out_unlock;
		}
		sscanf(arg, "%x", &len);

		// create the file
		bootcfg_create_locked(token, len);
	} else
		// delete a file
	if (strcmp(token, "delete") == 0) {
		// get our filename
		token = strsep(&ptr, " \n");
		if (token != NULL) {
			bootcfg_delete(token);
		}
	} else {

		// default case, we are just setting a variable
		if (*ptr != '\0') {
			arg = strsep(&ptr, "\n");
		} else {
			arg = NULL;
		}
		/* check if we have room to store another variable */
		if (!bootcfg_set_var_probe(token, arg))
			goto out_unlock;
		bootcfg_set_var_locked(token, arg);
		bootcfg_store_write();
	}
out_unlock:
	spin_unlock(&gBootCfgLock);
out:
	kfree(procfs_buffer);
	return count;
}

static void bootcfg_setFile(char *file, u32 addr, u32 len)
{
	char tmpBuf[256];

	// update our entry and end of memory marker
	sprintf(tmpBuf, "cfg 0x%08x 0x%08x", addr, len);
	bootcfg_set_var_locked(file, tmpBuf);

	sprintf(tmpBuf, "0x%08x", addr + len);
	bootcfg_set_var_locked("config_data_end", tmpBuf);
}

/******************************************************************************
	Function:   bootcfg_proc_write
	Purpose:	get data from proc file
 	Returns:	Number of bytes written, updates file->f_pos
  	Note:
 *****************************************************************************/
static int
bootcfg_proc_write(struct file *file, const char *buffer,
		   unsigned long count, void *data)
{
	char *procfs_buffer;
	ptsBootCfgFile id = (ptsBootCfgFile) data;
	char *p = (char *)&gBootCfgData.data[0];

	if ((procfs_buffer = kmalloc(count, GFP_KERNEL)) == NULL) {
		printk("bootcfg error: out of memory\n");
		return -ENOMEM;
	}

	/* write data to the buffer */
	if (copy_from_user(procfs_buffer, buffer, count)) {
		kfree(procfs_buffer);
		return -EFAULT;
	}
	/* write to bootcfg data file */
	//printk("bootcfg: write %s (%x) %d %d [%x]\n",id->entry,id->addr,(int)count,(int)file->f_pos,procfs_buffer[0]);

	spin_lock(&gBootCfgLock);
	// do we need to increase our size?
	if ((file->f_pos + count) > id->len) {
		int len = file->f_pos + count;
		u32 addr = bootcfg_get_end();

		if (addr + count > gBootCfgData.size) {
			printk("bootcfg error1: file too large\n");
			spin_unlock(&gBootCfgLock);
			kfree(procfs_buffer);
			return -ENOSPC;
		}

		if (id->addr == 0) {
			/* just need to allocate? */
			id->addr = addr;
			bootcfg_setFile(id->entry, addr, len);
		} else if ((id->addr + id->len) == addr) {
			/* just need to increase size */
			bootcfg_setFile(id->entry, id->addr, len);
		} else {
			u8 *orig;
			// make a copy of our data
			if ((orig = kmalloc(id->len, GFP_ATOMIC)) == NULL) {
				goto out;
			}
			memcpy(orig, &gBootCfgData.data[id->addr - 4], id->len);

			// remove our current file and defragment
			bootcfg_set_var_locked(id->entry, NULL);
			bootcfg_defragment_locked();

			// now add our new data
			addr = bootcfg_get_end();
			//printk("bootcfg: moving %s (%x->%x) %d %d\n",id->entry,id->addr,addr,len,(int)file->f_pos);

			// make sure we have room for data
			if ((addr + len) > gBootCfgData.size) {
				printk("bootcfg error2: file too large\n");

				// revert to flash data and return
				bootcfg_store_read();
				kfree(orig);
				goto out;
			}
			bootcfg_setFile(id->entry, addr, len);

			// copy our original data
			memcpy(p + addr - 4, orig, id->len);

			// update our fs info
			id->addr = addr;
			kfree(orig);
		}
		id->len = len;
	}
	// offset by 4 to compensate for crc
	memcpy((char *)&gBootCfgData.data[file->f_pos + id->addr - 4],
	       procfs_buffer, count);
	bootcfg_store_write_unsafe();
	id->proc->size = file->f_pos + count;
	file->f_pos += count;

 out:
	spin_unlock(&gBootCfgLock);
	kfree(procfs_buffer);
	return count;
}

/******************************************************************************
	Function:   bootcfg_get_args
	Purpose:	parse arguments from cfg file entry
	Returns:	filename copied to buffer, addr and len scanned and set
	Note:
 *****************************************************************************/
static void bootcfg_get_args(char *ptr, char *buffer, u32 * addr, u32 * len)
{
	while (*ptr != '=') {
		*buffer++ = *ptr++;
	}
	*buffer = 0;

	// figure out our addr and len from entry
	sscanf(ptr, "=cfg 0x%x 0x%x", addr, len);
}

/******************************************************************************
	Function:   bootcfg_defragment
	Purpose:	defragment bootcfg structure
	Returns:
	Note:	avoid some error checking by assuming data integrity.
		hopefully this is a safe assumption
 *****************************************************************************/
static int bootcfg_defragment_locked(void)
{
	char *ptr;
	u8 *data;
	char tmpBuf[64];
	u32 end = BOOT_CFG_DEF_START;
	ptsBootCfgFile next;

	// first make a copy of the entire buffer
	if ((data = (u8 *) kmalloc(BOOT_CFG_DATA_SIZE, GFP_ATOMIC)) == NULL) {
		return -ENOMEM;
	}

	memcpy(data, gBootCfgData.data, BOOT_CFG_DATA_SIZE);

	// loop through bootcfg file entries
	ptr = (char *)data;
	while (*ptr) {
		if (strstr(ptr, "=cfg") != 0) {
			u32 addr, len;
			char filename[256];

			// get current addr and len
			bootcfg_get_args(ptr, filename, &addr, &len);

			// copy data to new location
			memcpy(&gBootCfgData.data[end - 4], &data[addr - 4],
			       len);

			//printk("bootcfg defrag: moving %s from %x to %x\n",
			//    filename,addr,end);

			// save entry in env
			sprintf(tmpBuf, "cfg 0x%08x 0x%08x", end, len);
			bootcfg_set_var_locked(filename, tmpBuf);

			// update id
			next = gFiles;
			while (next != NULL) {
				if (strcmp(next->entry, filename) == 0) {
					next->addr = end;
					next->len = len;
					break;
				}
				next = next->next;
				// error check for null here without finding entry?
			}
			if (next == NULL) {
				// not much we can do here other than output a warning
				// should never happen - this is also engineering mode
				// only.  Production should never change a file size
				// or anything more than an ip or mac address, etc.
				printk("Bootcfg error: file information not found\n");
			}
			end += len;
		}
		// flush to 0, end marked by double 0
		while (*ptr++) {
		}
	}

	// update end of memory pointer
	sprintf(tmpBuf, "0x%08x", end);
	bootcfg_set_var_locked("config_data_end", tmpBuf);

	kfree(data);
	return 0;
}

/******************************************************************************
	Function:   bootcfg_proc_read
	Purpose:	read data from bootcfg flash area
 	Returns:
  	Note:  	Debug support file - displays register contents
 *****************************************************************************/
static int
bootcfg_proc_read(char *buffer,
		  char **buffer_location, off_t offset,
		  int buffer_length, int *eof, void *data)
{
	int len = 0;
	//printk("Proc read offset:%x len:%x\n",offset,buffer_length);

	spin_lock(&gBootCfgLock);

	if (data == NULL) {
		// this is env read
		char *ptr = (char *)&gBootCfgData.data[0];

		// we read on one shot
		if (offset > 0) {
			*eof = 1;
			spin_unlock(&gBootCfgLock);
			return 0;
		}

		while (*ptr) {
			len += sprintf(&buffer[len], "%s\n", ptr);
			while (*ptr++) {
			}
		}

	} else {
		// read from file
		ptsBootCfgFile id = (ptsBootCfgFile) data;
		//printk("reading %s (%x) %d %d\n",id->entry,id->addr,(int)offset,buffer_length);
		if (offset >= id->len) {
			// end of file
			*eof = 1;
			spin_unlock(&gBootCfgLock);
			return 0;
		}
		if (buffer_length > id->len) {
			len = id->len;
			*eof = 1;
			//printk("bootcfg error: len:%d > id->len:%d\n",buffer_length,id->len);
		} else if ((buffer_length + offset) > id->len) {
			len = id->len - offset;
			*eof = 1;
		} else {
			len = buffer_length;
		}

		if (len > PAGE_SIZE) {
			/*
			 * procfs has a limitation of one physical page per copy
			 * any buffer that exceeds the limit has to be split
			 */
			len = PAGE_SIZE;
			*eof = 0;
		}

		/*
		 * fs/proc/generic.c, L98: the value returned in *buffer_location
		 * has to be smaller than (unsigned long)buffer
		 */
		BUG_ON(PAGE_SIZE >= (unsigned long)buffer);
		*(unsigned long *)buffer_location = len;

		// compensate for crc
		memcpy(buffer,
			(char *)&gBootCfgData.data[id->addr - 4 + offset], len);
		//printk("data: %d %x %x\n",offset,buffer[offset],&gBootCfgData.data[id->addr-4+offset]);
		spin_unlock(&gBootCfgLock);
		return len;
	}
	spin_unlock(&gBootCfgLock);
	return (len + offset);
}

/******************************************************************************
	Function:   boardparam_proc_read
	Purpose:	read board paramaters
	Returns:
	Note:
 *****************************************************************************/
static int
boardparam_proc_read(char *buffer,
		  char **buffer_location, off_t offset,
		  int buffer_length, int *eof, void *data)
{
	int len = 0;

	if((len = bootcfg_get_all_hw_board_config(buffer)) < 0){
		printk("Failed to generate output\n");
		return(0);
	}

	return len;
}

static void
bootcfg_pending_proc_wait(void)
{
	int writes_pending = 1;

	while (writes_pending) {
		spin_lock(&gBootCfgLock);
		writes_pending = gBootCfgData.dirty;
		spin_unlock(&gBootCfgLock);

		if (writes_pending) {
			msleep(BOOTCFG_COMMIT_DELAY_MS + 1);
		}
	}
}

static int
bootcfg_pending_proc_read(char *buffer,
		  char **buffer_location, off_t offset,
		  int buffer_length, int *eof, void *data)
{
	int len = 0;

	bootcfg_pending_proc_wait();

	len += snprintf(&buffer[len], buffer_length - len, "%s writes complete\n", DRV_NAME);

	*eof = 1;

	return len;
}

/******************************************************************************
	Purpose:	override linux version to correct not suitable
			here write behaviour (position is not updated after
			write in original version)
 *****************************************************************************/
static ssize_t bootcfg_proc_file_write(struct file *file,
				       const char __user * buffer, size_t count,
				       loff_t * ppos);
static ssize_t bootcfg_proc_file_read(struct file *file, char __user * buf,
				      size_t nbytes, loff_t * ppos);
static loff_t bootcfg_proc_file_lseek(struct file *file, loff_t offset,
				      int orig);

struct bootcfg_file_operations {
	const struct file_operations wrapper;
	const struct file_operations *internal;
};

static struct bootcfg_file_operations bootcfg_proc_dir_operations = {
	.wrapper = {
		    .read = bootcfg_proc_file_read,
		    .write = bootcfg_proc_file_write,
		    .llseek = bootcfg_proc_file_lseek,
		    },
	.internal = NULL,
};

static ssize_t
bootcfg_proc_file_write(struct file *file, const char __user * buffer,
			size_t count, loff_t * ppos)
{
	ssize_t ret;
	if (!bootcfg_proc_dir_operations.internal) {
		panic("No function implementation\n");
	}
	ret =
	    bootcfg_proc_dir_operations.internal->write(file, buffer, count,
							ppos);
	if (ret > 0) {
		*ppos += ret;
	}
	return ret;
}

static ssize_t
bootcfg_proc_file_read(struct file *file, char __user * buf, size_t nbytes,
		       loff_t * ppos)
{
	if (!bootcfg_proc_dir_operations.internal) {
		panic("No function implementation\n");
	}
	return bootcfg_proc_dir_operations.internal->read(file, buf, nbytes,
							  ppos);
}

static loff_t
bootcfg_proc_file_lseek(struct file *file, loff_t offset, int orig)
{
	if (!bootcfg_proc_dir_operations.internal) {
		panic("No function implementation\n");
	}
	return bootcfg_proc_dir_operations.internal->llseek(file, offset, orig);
}

static void bootcfg_assign_file_fops(ptsBootCfgFile id)
{
	if (!id || !id->proc || !id->proc->proc_fops) {
		panic("Bad pointer.\n");
	}

	if (!bootcfg_proc_dir_operations.internal) {
		bootcfg_proc_dir_operations.internal = id->proc->proc_fops;
	}

	if (bootcfg_proc_dir_operations.internal != id->proc->proc_fops) {
		panic("Impossible\n");
	}

	id->proc->proc_fops = &(bootcfg_proc_dir_operations.wrapper);
}

/******************************************************************************
   Function:    bootcfg_mount
   Purpose:     Mount /proc/bootcfg file
   Returns:     pointer to device file
   Note:
 *****************************************************************************/
static ptsBootCfgFile bootcfg_mount(const char *filename, u32 addr, u32 len)
{
	ptsBootCfgFile id;
	// found a file, create an entry
	if ((id =
	     (ptsBootCfgFile) kmalloc(sizeof(tsBootCfgFile),
				      GFP_KERNEL)) == NULL) {
		printk("bootcfg: out of memory\n");
		return NULL;
	}
	strcpy(id->entry, filename);
	id->addr = addr;
	id->len = len;
	id->next = NULL;

	//printk("mounting /proc/bootcfg/%s, %x %x\n",id->entry,id->addr,id->len);

	if ((id->proc =
	     create_proc_entry(id->entry, 0x644, bootcfg_dir)) == NULL) {
		remove_proc_entry("bootcfg", bootcfg_dir);
		kfree(id);
		printk("unable to create /proc/bootcfg\n");
		return NULL;
	}
	id->proc->data = id;
	id->proc->read_proc = bootcfg_proc_read;
	id->proc->write_proc = bootcfg_proc_write;
	id->proc->mode = S_IFREG | S_IRUGO;
	id->proc->uid = 0;
	id->proc->gid = 0;
	id->proc->size = len;
	bootcfg_assign_file_fops(id);
	return id;
}

/******************************************************************************
   Function:    bootcfg_find_hw_config_file
   Purpose:     Locate qtn_hw_board_config file in uboot env
   Returns:     pointer to the file structure, NULL otherwise
   Note:
 *****************************************************************************/
static ptsBootCfgFile bootcfg_find_hw_config_file(void)
{
	ptsBootCfgFile nextFile = gFiles;

	while (nextFile != NULL) {
		if(strcmp(nextFile->entry, QTN_HW_BOARD_CFG_BIN) == 0)
			return nextFile;
		nextFile = nextFile->next;
	}
	return NULL;
}

extern int qtn_get_hw_config_id(void);

static const char * const board_config_type2name[] = BOARD_CFG_FIELD_NAMES;


/******************************************************************************
   Function:    bootcfg_parse_hw_board_config_tlv
   Purpose:     Parse single TLV from the flash memory
   Returns:     NULL in case of error or ptr to the next TLV on success
   Note:
 *****************************************************************************/
static uint8_t* bootcfg_parse_hw_board_config_tlv(uint8_t *ptr, uint8_t *end_ptr,
	uint16_t *type, char *text, int *data, uint8_t *data_size)
{
#ifndef UINT8_MAX
#define UINT8_MAX		(uint8_t)(~((uint8_t)0))
#endif

/* Min size means zero size text and zero size data */
#define TLV_MIN_SIZE		(4)
#define TLV_TEXT_SIZE(ptr)	(ptr[2])
#define TLV_DATA_SIZE(ptr)	(ptr[3 + TLV_TEXT_SIZE(ptr)])
#define TLV_SIZE(ptr)		(TLV_MIN_SIZE + TLV_TEXT_SIZE(ptr) + TLV_DATA_SIZE(ptr))

	if(end_ptr - ptr < TLV_SIZE(ptr))
		return NULL;

	/* Type of TLV */
	memcpy(type, ptr, sizeof(*type));
	ptr += sizeof(*type);

	/* Text length of TLV*/
	uint8_t size = *ptr;
	++ ptr;

	/* Text of TLV */
	if (text)
		memcpy(text, ptr, size);
	ptr += size;

	/* Data length of TLV */
	size = *ptr;
	if (data_size)
		*data_size = size;
	++ ptr;

	/* Data of TLV */
	if (data)
		memcpy(data, ptr, size);
	ptr += size;

	return ptr;
}

/******************************************************************************
   Function:    bootcfg_get_hw_board_config
   Purpose:     Return required board configuration
   Returns:     0 if parameter found, ENODEV or EINVAL otherwise
   Note:	Should be called while gBootCfgLock is held
 *****************************************************************************/
int bootcfg_get_hw_board_config(uint16_t type, char *text, int *data)
{
	if (qtn_get_hw_config_id() != QTN_RUBY_UNIVERSAL_BOARD_ID)
		return get_board_config(type, data);

	if (type > ARRAY_SIZE(board_config_type2name))
		return -EINVAL;

	spin_lock(&gBootCfgLock);

	ptsBootCfgFile hw_config_file = bootcfg_find_hw_config_file();
	if (!hw_config_file)
	{
		spin_unlock(&gBootCfgLock);
		return -ENODEV;
	}

	uint8_t *file_ptr =
		gBootCfgData.data - offsetof(tsBootCfgData, data) + hw_config_file->addr;
	uint8_t *file_end_ptr = file_ptr + hw_config_file->len;
	int retval = -EINVAL;

	while (file_ptr < file_end_ptr) {
		uint16_t parsed_type = 0;
		/* Introduce tmp_data here to avoid changing data if type is not found.
		 * Otherwise we can chancge default value set by caller.
		 */
		int tmp_data = 0;

		file_ptr = bootcfg_parse_hw_board_config_tlv(file_ptr, file_end_ptr,
				&parsed_type, text, &tmp_data, NULL);

		if (!file_ptr)
			break;

		if (type + 1 == parsed_type) {
			retval = 0;
			if (data)
				memcpy(data, &tmp_data, sizeof(*data));
			break;
		}

	}

	spin_unlock(&gBootCfgLock);

	return retval;
}

EXPORT_SYMBOL(bootcfg_get_hw_board_config);

/******************************************************************************
   Function:    bootcfg_get_all_hw_board_config
   Purpose:     Return all params packed in one char buffer
   Returns:     0 if there is an error, number of bytes otherwise
   Note:
 *****************************************************************************/
static int bootcfg_get_all_hw_board_config(char *buffer)
{
	if (!buffer)
		return 0;

	if (qtn_get_hw_config_id() != QTN_RUBY_UNIVERSAL_BOARD_ID)
		return get_all_board_params(buffer);

	spin_lock(&gBootCfgLock);

	ptsBootCfgFile hw_config_file = bootcfg_find_hw_config_file();
	if (!hw_config_file)
	{
		spin_unlock(&gBootCfgLock);
		return -ENODEV;
	}

	uint8_t *file_ptr =
		gBootCfgData.data - offsetof(tsBootCfgData, data) + hw_config_file->addr;
	uint8_t *file_end_ptr = file_ptr + hw_config_file->len;
	int ch_printed = 0;
	char *buffer_ptr = buffer;

	while (file_ptr < file_end_ptr) {
		uint16_t parsed_type = 0;
		char parsed_text[UINT8_MAX + 1] = {0};
		int parsed_data = 0;
		uint8_t  parsed_data_size = 0;

		file_ptr = bootcfg_parse_hw_board_config_tlv(file_ptr, file_end_ptr,
				&parsed_type, parsed_text, &parsed_data, &parsed_data_size);

		if (!file_ptr)
			break;

		if (parsed_type > ARRAY_SIZE(board_config_type2name) || parsed_type == 0)
			continue;

		int current_ch_printed;

		/* Assumes that if data size is zero then text is
		 * supposed to be used
		 */
		if(parsed_data_size == 0) {
			/* Add offset 3 to remove "bc_" prefix from names. */
			current_ch_printed = snprintf(buffer_ptr, PAGE_SIZE - ch_printed,
							"%-23s%s\n",
							board_config_type2name[parsed_type - 1] + 3,
							parsed_text);
		} else {
			current_ch_printed = snprintf(buffer_ptr, PAGE_SIZE - ch_printed,
							"%-23s%d\n",
							board_config_type2name[parsed_type - 1] + 3,
							parsed_data);
		}

		if (current_ch_printed < 0)
			break;

		ch_printed += current_ch_printed;
		buffer_ptr += current_ch_printed;
	}

	spin_unlock(&gBootCfgLock);
	return ch_printed;
}

/******************************************************************************
   Function:    bootcfg_init
   Purpose:     Set up crctable, and initialize module
   Returns:
   Note:
 *****************************************************************************/
static int __init bootcfg_init(void)
{
	char *next;
	int err;
	ptsBootCfgFile nextFile = gFiles;

	spin_lock_init(&gBootCfgLock);

	err = bootcfg_store_init();
	if (err) {
		goto out;
	}

	// read the bootcfg data
	err = bootcfg_store_read();
	if (err != 0) {
		goto out_exit_store;
	}
	gBootCfgData.isValid = 1;
	gBootCfgData.dirty = 0;

	// create a proc entry
	bootcfg_dir = proc_mkdir("bootcfg", NULL);

	if ((bootcfg_proc = create_proc_entry("env", 0x644, bootcfg_dir)) == NULL) {
		printk(KERN_ERR "unable to create /proc/bootcfg/%s\n", "env");
		goto out_exit_env;
	}
	bootcfg_proc->read_proc = bootcfg_proc_read;
	bootcfg_proc->write_proc = bootcfg_proc_write_env;
	bootcfg_proc->mode = S_IFREG | S_IRUGO;
	bootcfg_proc->uid = 0;
	bootcfg_proc->gid = 0;
	bootcfg_proc->size = 0x1000;
	bootcfg_proc->data = NULL;

	if ((boardparam_proc = create_proc_entry("boardparam", 0x444, bootcfg_dir)) == NULL) {
		printk(KERN_ERR "unable to create /proc/bootcfg/%s\n", "boardparam");
		goto out_exit_boardparam;
	}
	boardparam_proc->read_proc = boardparam_proc_read;
	boardparam_proc->write_proc = NULL;
	boardparam_proc->mode = S_IFREG | S_IRUGO;
	boardparam_proc->uid = 0;
	boardparam_proc->gid = 0;
	boardparam_proc->data = NULL;

	if ((pending_proc = create_proc_entry("pending", 0x444, bootcfg_dir)) == NULL) {
		printk(KERN_ERR "unable to create /proc/bootcfg/%s\n", "pending");
		goto out_exit_pending;
	}
	pending_proc->read_proc = bootcfg_pending_proc_read;
	pending_proc->write_proc = NULL;
	pending_proc->mode = S_IFREG | S_IRUGO;
	pending_proc->uid = 0;
	pending_proc->gid = 0;
	pending_proc->data = NULL;

	// now look for files in bootcfg
	next = (char *)gBootCfgData.data;
	while (*next) {
		if (strstr(next, "=cfg") != 0) {
			u32 addr, len;
			char buffer[256];
			bootcfg_get_args(next, buffer, &addr, &len);
			if (gFiles == NULL) {
				gFiles = bootcfg_mount(buffer, addr, len);
			} else {
				nextFile = gFiles;
				while (nextFile->next != NULL) {
					nextFile = nextFile->next;
				}
				nextFile->next =
				    bootcfg_mount(buffer, addr, len);
			}

		}
		// flush to next entry
		while (*next++) {
		}
	}

	return 0;

out_exit_pending:
	remove_proc_entry("boardparam", bootcfg_dir);
out_exit_boardparam:
	remove_proc_entry("env", bootcfg_dir);
out_exit_env:
	err = -ENOMEM;
	remove_proc_entry("bootcfg", bootcfg_dir);
out_exit_store:
	bootcfg_store_exit();
out:
	return err;
}

/******************************************************************************
   Function:    bootcfg_exit
   Purpose:     exit our driver
   Returns:
   Note:
 *****************************************************************************/
static void __exit bootcfg_exit(void)
{
	ptsBootCfgFile nextFile = gFiles;
	ptsBootCfgFile prev;

	bootcfg_store_exit();

	while (nextFile != NULL) {
		remove_proc_entry(nextFile->entry, bootcfg_dir);
		prev = nextFile;
		nextFile = nextFile->next;
		kfree(prev);
	}
	remove_proc_entry("env", bootcfg_dir);
	remove_proc_entry("boardparam", bootcfg_dir);
	remove_proc_entry("pending", bootcfg_dir);
	remove_proc_entry("bootcfg", NULL);

	bootcfg_pending_proc_wait();

	printk(KERN_ALERT "bootcfg Driver Terminated\n");
}

/******************************************************************************
   Function:Linux driver entries/declarations
 *****************************************************************************/
module_init(bootcfg_init);
module_exit(bootcfg_exit);
MODULE_LICENSE("GPL");
