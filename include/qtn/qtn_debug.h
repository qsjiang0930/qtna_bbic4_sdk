/**
  Copyright (c) 2008 - 2017 Quantenna Communications Inc
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

#ifndef QTN_DEBUG_H_
#define QTN_DEBUG_H_

/* When set to 1 LHOST formats AuC print output. It is not possible to use %s and %pM
conversion specifiers. Also the number of arguments printed are limited to 8 and therefore
stack size is limited to 32.
When set to 0 AuC formats the output, pass the formatted line to the LHOST that
prints it. */
#define AUC_LHOST_PRINT_FORMAT	1
#define PRINT_STACK_SIZE	32

#if defined(MUC_BUILD)
#define	DBGFN		uc_printk
#elif defined(AUC_BUILD)
#define	DBGFN		auc_os_printf
#else
#define	DBGFN		printk
#endif

#ifndef __GNUC__
#define __FUNCTION__	""
#endif

#define DBGFMT  "%s: "
#define DBGEFMT "%s: ERROR - "
#define DBGWFMT "%s: WARNING - "
#define DBGARG  __func__
#define DBGMACVAR "%02x:%02x:%02x:%02x:%02x:%02x"
#define DBGMACFMT(a) \
	(a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define DBGMACFMT_LE(a) \
	(a)[5], (a)[4], (a)[3], (a)[2], (a)[1], (a)[0]

#define DBGFMT_BYTEFLD3_P	"%u.%u.%u"
#define DBGFMT_BYTEFLD3_V(_v)	(_v >> 16) & 0xff, (_v >> 8) & 0xff, _v & 0xff
#define DBGFMT_BYTEFLD4_P	"%u.%u.%u.%u"
#define DBGFMT_BYTEFLD4_V(_v)	(_v >> 24) & 0xff, (_v >> 16) & 0xff, (_v >> 8) & 0xff, _v & 0xff

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

typedef enum {
	DBG_LM_QDRV = 1,
	DBG_LM_QPCIE,
	DBG_LM_QRADAR,
	DBG_LM_QBOOTCFG,
	DBG_LM_QADM,
	DBG_LM_QWLAN,
	DBG_LM_QMACFW,
	DBG_LM_MAX
} dbg_log_module;

extern unsigned int g_dbg_log_module;

#if defined(MUC_BUILD)
extern unsigned int g_dbg_log_level;
extern unsigned int g_dbg_log_func;
#else
extern unsigned int g_dbg_log_level[DBG_LM_MAX];
extern unsigned int g_dbg_log_func[DBG_LM_MAX];
#endif

#define DBG_LL_EMERG					0
#define DBG_LL_ALERT					1
#define DBG_LL_ERR					2
#define DBG_LL_WARNING					3
#define DBG_LL_CRIT					4
#define DBG_LL_NOTICE					5
#define DBG_LL_INFO					6
#define DBG_LL_HIDDEN					7
#define DBG_LL_DEBUG					8
#define DBG_LL_TRIAL					9
#define DBG_LL_ALL					10

#define DBG_LF_00					0x00000001
#define DBG_LF_01					0x00000002
#define DBG_LF_02					0x00000004
#define DBG_LF_03					0x00000008
#define DBG_LF_04					0x00000010
#define DBG_LF_05					0x00000020
#define DBG_LF_06					0x00000040
#define DBG_LF_07					0x00000080
#define DBG_LF_08					0x00000100
#define DBG_LF_09					0x00000200
#define DBG_LF_10					0x00000400
#define DBG_LF_11					0x00000800
#define DBG_LF_12					0x00001000
#define DBG_LF_13					0x00002000
#define DBG_LF_14					0x00004000
#define DBG_LF_15					0x00008000
#define DBG_LF_16					0x00010000
#define DBG_LF_17					0x00020000
#define DBG_LF_18					0x00040000
#define DBG_LF_19					0x00080000
#define DBG_LF_20					0x00100000
#define DBG_LF_21					0x00200000
#define DBG_LF_22					0x00400000
#define DBG_LF_23					0x00800000
#define DBG_LF_24					0x01000000
#define DBG_LF_25					0x02000000
#define DBG_LF_26					0x04000000
#define DBG_LF_27					0x08000000
#define DBG_LF_28					0x10000000
#define DBG_LF_29					0x20000000
#define DBG_LF_30					0x40000000
#define DBG_LF_31					0x80000000
#define DBG_LF_ALL					0xFFFFFFFF

#define DBG_LOG_FUNC (g_dbg_log_func[DBG_LM - 1])
#define DBG_LOG_LEVEL (g_dbg_log_level[DBG_LM - 1])
#define DBG_LOG_FUNC_TEST(flag) (g_dbg_log_func[DBG_LM - 1] & (flag))

#if defined(QTN_DEBUG)

#define DBGPRINTF_RAW(ll, lf, fmt, ...)						\
	do {									\
		if((g_dbg_log_module & (BIT(DBG_LM - 1))) &&			\
				(DBG_LOG_LEVEL >= (ll)) &&			\
				(DBG_LOG_FUNC_TEST(lf))) {			\
			DBGFN(fmt, ##__VA_ARGS__);				\
		}								\
	} while(0)

#define DBGPRINTF(ll, lf, fmt, ...)						\
	do {									\
		if((g_dbg_log_module & (BIT(DBG_LM - 1))) &&			\
				(DBG_LOG_LEVEL >= (ll)) &&			\
				(DBG_LOG_FUNC_TEST(lf))) {			\
			DBGFN(DBGFMT fmt, DBGARG, ##__VA_ARGS__);		\
		}								\
	} while(0)

#define DBGPRINTF_E(fmt, ...)							\
	do {									\
		if (DBG_LOG_LEVEL >= DBG_LL_ERR)				\
			DBGFN(DBGEFMT fmt, DBGARG, ##__VA_ARGS__);		\
	} while(0)

#define DBGPRINTF_W(fmt, ...)							\
	do {									\
		if (DBG_LOG_LEVEL >= DBG_LL_WARNING)				\
			DBGFN(DBGWFMT fmt, DBGARG, ##__VA_ARGS__);		\
	} while(0)

#define DBGPRINTF_N(fmt, ...)							\
	DBGFN(fmt, ##__VA_ARGS__);

#define DBGPRINTF_LIMIT_E(fmt, ...)						\
	do {									\
		if ((DBG_LOG_LEVEL >= DBG_LL_ERR) && (net_ratelimit()))		\
			DBGFN(DBGEFMT fmt, DBGARG, ##__VA_ARGS__);		\
	} while(0)

#define DBGPRINTF_LIMIT(ll, lf, fmt, ...)					\
	do {									\
		if ((g_dbg_log_module & BIT(DBG_LM - 1)) &&			\
			DBG_LOG_FUNC_TEST(lf) &&				\
			DBG_LOG_LEVEL >= (ll) && (net_ratelimit()))		\
			DBGFN(DBGFMT fmt, DBGARG, ##__VA_ARGS__);		\
	} while(0)
#else
#define DBGPRINTF(ll, lf, fmt, args...)
#define DBGPRINTF_E(fmt, args...)
#define DBGPRINTF_W(fmt, args...)
#define DBGPRINTF_LIMIT_E(fmt, args...)
#define DBGPRINTF_LIMIT(ll, lf, fmt, args...)
#endif

#define HERE(x) do {							\
	DBGFN("%s:%d:%s %s = %d 0x%x\n",				\
			__FILE__, __LINE__, __FUNCTION__, (#x),		\
			(int) (x), (unsigned int) (x));			\
} while(0)

#define HERES(x) do {							\
	DBGFN("%s:%d:%s %s = '%s'\n",					\
			__FILE__, __LINE__, __FUNCTION__, (#x), (x));	\
} while(0)

#define HERE_REG(addr)	do {						\
	DBGFN("%s:%d:%s reg 0x%08lx = 0x%08lx (%s)\n",			\
			__FILE__, __LINE__, __FUNCTION__,		\
			(unsigned long) (addr),				\
			(unsigned long) readl(addr), (#addr));		\
} while(0)

#endif /* QTN_DEBUG_H_ */
