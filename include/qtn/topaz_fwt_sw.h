/**
 * Copyright (c) 2014 - 2017 Quantenna Communications Inc
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

#ifndef FWT_SW_H_
#define FWT_SW_H_


#include <linux/types.h>
#include <qtn/topaz_fwt_db.h>
#include <qtn/topaz_fwt_if.h>

/* Success definition in FWT Interface is return positive value */
#define FWT_IF_SUCCESS(x)	((x) >= 0)
/* Error definition in FWT Interface is return negative value */
#define FWT_IF_ERROR(x)		(!(FWT_IF_SUCCESS(x)))

/*
 * Register overwrite entries for second level entry delete protocol from FWT table
 * @param dst_index: Index to be overwritten
 * @param src_index: Source index
 * */
void topaz_fwt_register_overwrite_entries(uint16_t dst_index,uint16_t src_index);

/*
 * Register a node
 * @param node_num: node number
 * @param vap_idx: vap index
 */
void fwt_sw_register_node(uint16_t node_num);

/*
 * Unregister a node
 * @param node_num: node number
 * @param vap_idx: vap index
 */
void fwt_sw_unregister_node(uint16_t node_num);

/*
 * Add device to the FWT.
 * If successful, update the FWT mirror table and the node list at the fwt database
 *
 * @param mac_id: MAC ID in big endian presentation
 * @param port_id: the port number. Note: must match the FWT HW presentation.
 * @param node_num: the node number
 * @param ip_map: Multicast aliasing bit identifier.
 * @return success / failure indication.
 */
int fwt_sw_add_device(const uint8_t *mac_be, uint8_t port_id, uint8_t node_num,
		const struct br_ip *group);

/*
 * Flag 4-address support for a MAC address
 * @param mac_be: mac id in big endian presentation
 * @param addr: Support indication for 4 address method
 */
int fwt_sw_set_4_address_support(const uint8_t *mac_be, int use_4addr);
/*
 * Reset call will clear both HW and Software FWT tables
 */
void fwt_sw_reset(void);

/*
 * Print both node list and FWT table
 */
int fwt_sw_print(void);


/* Inidicate expiry time
 * @param mac_be: mac id in big endian presentation
 */
int fwt_sw_get_timestamp(const uint8_t *mac_be);

/*
 * Delete device entry from both HW and SW FWT tables
 * @param mac_be: MAC in big endian
 */
int fwt_sw_delete_device(const uint8_t *mac_be);

/*
 * Update or insert new FWT table entry from multicast IGMP message.
 * @param node: node number.
 * @param port_id: output port.
 * @param group: Indication for the multicast address by group id.
 */
int fwt_sw_join_multicast(uint8_t node, uint8_t port_id,
		const struct br_ip *group);
/*
 * Remove or delete node from the FWT table entry from multicast IGMP message.
 * @param node: node number.
 * @param port_id: output port.
 * @param group: Indication for the multicast address by group id.
 */
int fwt_sw_leave_multicast(uint8_t node, uint8_t port_id,
		const struct br_ip *group);

typedef int (*fwt_sw_4addr_callback_t)(void *token, uint8_t port_id,
		uint8_t node_num);

typedef uint8_t (*fwt_sw_remapper_t)(uint8_t in_port, const uint8_t *mac_be);

void fwt_sw_register_port_remapper(uint8_t port, fwt_sw_remapper_t remapper);

/**
 * Callback to determine whether a FWT table entry should be added as 4 address mode or not.
 * Typically registered by qdrv
 * @param callback: callback function pointer to register
 * @param token: will always be provided to the callback when invoked, as the first argument
 */
void fwt_sw_4addr_callback_set(fwt_sw_4addr_callback_t callback, void *token);

/* Get number of current entries */
uint16_t fwt_sw_get_entries_cnt(void);

int fwt_sw_cmd(fwt_if_usr_cmd cmd, struct fwt_if_common *data);

int fwt_sw_get_index_from_mac_be(const uint8_t *mac_be);

/*
 * Fast way to get fwt entry for unicast packet
 * @param src_mac_be: source mac address of the packet
 * @param dst_mac_be: destination mac address of the packet
 */
fwt_db_entry *fwt_sw_fast_get_ucast_entry(const unsigned char *src_mac_be,
		const unsigned char *dst_mac_be);

void fwt_sw_update_false_miss(int index, uint8_t false_miss);

int fwt_sw_get_ipff(char *buf, int buflen);

extern dma_addr_t ipmac_hash_bus;
extern dma_addr_t ipmac_base_bus;

int fwt_sw_update_uc_ipmac(const uint8_t *mac_be, const uint8_t *ip, uint16_t type);

void fwt_sw_remove_uc_ipmac(const uint8_t *ip, uint16_t type);

extern int fwt_sw_get_node_from_mac(const unsigned char *mac_be);
#endif /* FWT_INTERFACE_H_ */
