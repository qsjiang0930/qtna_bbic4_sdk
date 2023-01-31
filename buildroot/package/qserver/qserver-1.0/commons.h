/*
 *		commons.h
 *
 * Copyright (c) 2016 Quantenna Communications, Inc.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#ifndef COMMONS_H
#define COMMONS_H

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#define __USE_GNU
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <getopt.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


#define QSERVER_PATH_MAX		108
#define QSERVER_DEFAULT_IFACE		"wifi0"
#define QSERVER_DEFAULT_DRV_NAME	"Quantenna"
#define QSERVER_MSG_BUF_LEN		8192
#define QSERVER_CMD_MAX_LEN		256

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(X)  (sizeof(X)/sizeof(X[0]))
#endif

#ifndef UNUSED_PARAM
#define UNUSED_PARAM __attribute__ ((__unused__))
#endif

#define broadcast_ethaddr (uint8_t *)"\xff\xff\xff\xff\xff\xff"

#define OS_PUT_BE16(a, val)			\
	do {					\
		(a)[0] = ((uint16_t) (val)) >> 8;	\
		(a)[1] = ((uint16_t) (val)) & 0xff;	\
	} while (0)
#define OS_PUT_BE32(a, val)					\
	do {							\
		(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)
#define OS_PUT_BE64(a, val)				\
	do {						\
		(a)[0] = (uint8_t) (((uint64_t) (val)) >> 56);	\
		(a)[1] = (uint8_t) (((uint64_t) (val)) >> 48);	\
		(a)[2] = (uint8_t) (((uint64_t) (val)) >> 40);	\
		(a)[3] = (uint8_t) (((uint64_t) (val)) >> 32);	\
		(a)[4] = (uint8_t) (((uint64_t) (val)) >> 24);	\
		(a)[5] = (uint8_t) (((uint64_t) (val)) >> 16);	\
		(a)[6] = (uint8_t) (((uint64_t) (val)) >> 8);	\
		(a)[7] = (uint8_t) (((uint64_t) (val)) & 0xff);	\
	} while (0)

#define OS_PUT_LE16(a, val)			\
	do {					\
		(a)[1] = ((uint16_t) (val)) >> 8;	\
		(a)[0] = ((uint16_t) (val)) & 0xff;	\
	} while (0)
#define OS_PUT_LE32(a, val)					\
	do {							\
		(a)[3] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[0] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)
#define OS_PUT_LE64(a, val)				\
	do {						\
		(a)[7] = (uint8_t) (((uint64_t) (val)) >> 56);	\
		(a)[6] = (uint8_t) (((uint64_t) (val)) >> 48);	\
		(a)[5] = (uint8_t) (((uint64_t) (val)) >> 40);	\
		(a)[4] = (uint8_t) (((uint64_t) (val)) >> 32);	\
		(a)[3] = (uint8_t) (((uint64_t) (val)) >> 24);	\
		(a)[2] = (uint8_t) (((uint64_t) (val)) >> 16);	\
		(a)[1] = (uint8_t) (((uint64_t) (val)) >> 8);	\
		(a)[0] = (uint8_t) (((uint64_t) (val)) & 0xff);	\
	} while (0)

#define OS_GET_BE16(a) ((((uint16_t) (a)[0]) << 8) | ((uint16_t) (a)[1]))
#define OS_GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | \
			(((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))
#define OS_GET_BE64(a) ((((uint64_t) (a)[0]) << 56) | (((uint64_t) (a)[1]) << 48) | \
			(((uint64_t) (a)[2]) << 40) | (((uint64_t) (a)[3]) << 32) | \
			(((uint64_t) (a)[4]) << 24) | (((uint64_t) (a)[5]) << 16) | \
			(((uint64_t) (a)[6]) << 8) | ((uint64_t) (a)[7]))

#define OS_GET_LE16(a) ((((uint16_t) (a)[1]) << 8) | ((uint16_t) (a)[0]))
#define OS_GET_LE32(a) ((((uint32_t) (a)[3]) << 24) | (((uint32_t) (a)[2]) << 16) | \
			(((uint32_t) (a)[1]) << 8) | ((uint32_t) (a)[0]))
#define OS_GET_LE64(a) ((((uint64_t) (a)[7]) << 56) | (((uint64_t) (a)[6]) << 48) | \
			(((uint64_t) (a)[5]) << 40) | (((uint64_t) (a)[4]) << 32) | \
			(((uint64_t) (a)[3]) << 24) | (((uint64_t) (a)[2]) << 16) | \
			(((uint64_t) (a)[1]) << 8) | ((uint64_t) (a)[0]))


typedef long os_time_t;

struct os_time {
	os_time_t sec;
	os_time_t usec;
};


void os_fprintf(FILE *stream, const char *fmt, ...);

/*
 * gcc 4.4 ends up generating strict-aliasing warnings about some very common
 * networking socket uses that do not really result in a real problem and
 * cannot be easily avoided with union-based type-punning due to struct
 * definitions including another struct in system header files. To avoid having
 * to fully disable strict-aliasing warnings, provide a mechanism to hide the
 * typecast from aliasing for now. A cleaner solution will hopefully be found
 * in the future to handle these cases.
 */
static inline void * __hide_aliasing_typecast(void *foo)
{
	return foo;
}
#define aliasing_hide_typecast(a,t) (t *) __hide_aliasing_typecast((a))

int os_get_time(struct os_time *t);

static inline int os_time_before(struct os_time *a,
	struct os_time *b)
{
	return (a->sec < b->sec) ||
	       (a->sec == b->sec && a->usec < b->usec);
}

static inline void os_time_sub(struct os_time *a, struct os_time *b,
			       struct os_time *res)
{
	res->sec = a->sec - b->sec;
	res->usec = a->usec - b->usec;
	if (res->usec < 0) {
		res->sec--;
		res->usec += 1000000;
	}
}

static inline void * os_zalloc(size_t size)
{
	return calloc(1, size);
}

static inline int os_hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static inline int os_hex2byte(const char *hex)
{
	int a, b;
	a = os_hex2num(*hex++);
	if (a < 0)
		return -1;
	b = os_hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

int os_hexstr2bin(const char *hex, uint8_t *buf, size_t len);

int os_snprintf_hex(char *buf, size_t buf_size,
	const uint8_t *data, size_t len);

int os_hwaddr_aton(const char *txt, uint8_t *addr);

int os_random_array(unsigned char *data,
	int len, unsigned int ext_seed);


#endif /* COMMONS_H */
