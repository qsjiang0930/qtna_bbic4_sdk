/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 */

#ifndef _QTN_ENDIAN_H_
#define _QTN_ENDIAN_H_

#include <endian.h>
#include <byteswap.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define htoqt16(x) (x)
#define qt16toh(x) (x)
#define htoqt32(x) (x)
#define qt32toh(x) (x)
#define htoqt64(x) (x)
#define qt64toh(x) (x)

#else

#define htoqt16(x) __bswap_16(x)
#define qt16toh(x) __bswap_16(x)
#define htoqt32(x) __bswap_32(x)
#define qt32toh(x) __bswap_32(x)
#define htoqt64(x) __bswap_64(x)
#define qt64toh(x) __bswap_64(x)

#endif

#endif /* _QTN_ENDIAN_H_ */
