/*
 * Copyright (c) 2016 Quantenna Communications, Inc.
 * All rights reserved.
 */

#ifndef QFTP_ENDIAN_H_
#define QFTP_ENDIAN_H_

#include <endian.h>
#include <byteswap.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define htoqt16(x) (x)
#define qt16toh(x) (x)
#define htoqt32(x) (x)
#define qt32toh(x) (x)

#else

#define htoqt16(x) __bswap_16(x)
#define qt16toh(x) __bswap_16(x)
#define htoqt32(x) __bswap_32(x)
#define qt32toh(x) __bswap_32(x)

#endif

#endif /* QFTP_ENDIAN_H_ */
