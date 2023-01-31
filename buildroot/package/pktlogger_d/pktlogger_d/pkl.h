/*
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : pkl.h                                                      **
**  Description : API to communicate with pktlogger. Not multi-thread safe.  **
**                A single instance of pkl per process is supported.         **
**                                                                           **
*******************************************************************************
*/

#ifndef PKL_H
#define PKL_H

#include <stdint.h>
#include "pktlogger_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PKL_API_VERSION	"1.0.2"

#define PKL_RECV_BUF_MAX_SIZE	65535 /* max UDP packet size */

#define PKL_DBG_ERROR		0
#define PKL_DBG_WARNING		1
#define PKL_DBG_MESSAGE		2

extern void pkl_debug_pk_verbose_set(void *desc, int level);

extern int  pkl_debug_pk_config_set(void *desc, const struct pktlogger_config_t *cfg);
extern int  pkl_debug_pk_config_get(void *desc, struct pktlogger_config_t *cfg);

extern int  pkl_debug_pk_config_one_set(void *desc, const struct pktlogger_config_one_t *cfg);
extern int  pkl_debug_pk_config_one_get(void *desc, struct pktlogger_config_one_t *cfg, int radio_index, int type);

extern int  pkl_debug_pk_type_config_set(int index, int hist_prior, int hist_total,
		const struct pktlogger_ptype_config_t param_config[], unsigned int param_count);
extern int  pkl_debug_pk_type_config_get(void *desc, int index, int *hist_prior, int *hist_total,
		struct pktlogger_ptype_config_t *param_config[], unsigned int *param_count);

extern int  pkl_debug_pk_type_data_config_all_set(void *desc, int index, int hist_len, int stats_type);

extern int  pkl_debug_pk_get_stream_socket(void *desc, int *sock);
extern int  pkl_debug_pk_send_stream_request(void *desc, int radio_index, int type,
                                             uint16_t history_count, uint32_t flags);
extern int  pkl_debug_pk_recv_data(void *desc, uint8_t *data, unsigned int *data_len, int *type);
extern int  pkl_debug_pk_stop_stream(void *desc, int radio_index, int type);

extern int  pkl_debug_pk_get_compressed_structure(void *desc, uint8_t *lzma_structs, uint32_t *structs_size);

extern int  pkl_open(void **desc, int port, uint8_t *lzma_structs, uint32_t *structs_size);
extern void pkl_close(void *desc);

#ifdef __cplusplus
}
#endif

#endif /* PKL_H */
