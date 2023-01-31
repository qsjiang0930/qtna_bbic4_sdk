/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2017 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : qtn_wmm_ac.h                                               **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _QTN_WMM_AC_H
#define _QTN_WMM_AC_H

#define WMM_AC_BE	0
#define WMM_AC_BK	1
#define WMM_AC_VI	2
#define WMM_AC_VO	3
#define WMM_AC_NUM	4
#define QTN_AC_MGMT	WMM_AC_VO
#define WMM_AC_INVALID	WMM_AC_NUM

#define QTN_AC_ORDER	{ WMM_AC_VO, WMM_AC_VI, WMM_AC_BE, WMM_AC_BK }
#define QTN_AC_ORDER_NUM	4

#define QTN_TID_BE	0
#define QTN_TID_BK	1
#define QTN_TID_2	2
#define QTN_TID_3	3
#define QTN_TID_WLAN	4	/* 802.11 encap'ed data from wlan driver */
#define QTN_TID_VI	5
#define QTN_TID_VO	6
#define QTN_TID_MGMT	7
#define QTN_TID_NUM	8
#define QTN_TID_IS_80211(tid)	((tid == QTN_TID_MGMT) || (tid == QTN_TID_WLAN))

#define QTN_TID_ORDER	{ \
	QTN_TID_MGMT,	\
	QTN_TID_WLAN,	\
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK	\
}
#define QTN_TID_ORDER_NUM	6

#define QTN_TID_ORDER_DATA { \
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK	\
}
#define QTN_TID_ORDER_DATA_NUM	4

/* Must contain all TIDs. Management should be the last. */
#define QTN_TID_ORDER_POLL { \
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK,	\
	QTN_TID_WLAN,	\
	QTN_TID_MGMT	\
}
#define QTN_TID_ORDER_POLL_NUM	6

#define WMM_AC_TO_TID(_ac) (			\
	(_ac == WMM_AC_VO) ? QTN_TID_VO :	\
	(_ac == WMM_AC_VI) ? QTN_TID_VI :	\
	(_ac == WMM_AC_BK) ? QTN_TID_BK :	\
	QTN_TID_BE)

#define TID_TO_WMM_AC(_tid) (		\
	(_tid == QTN_TID_BK)	? WMM_AC_BK :	\
	(_tid == QTN_TID_VI)	? WMM_AC_VI :	\
	(_tid == QTN_TID_VO)	? WMM_AC_VO :	\
	(_tid == QTN_TID_WLAN)	? QTN_AC_MGMT :	\
	(_tid == QTN_TID_MGMT)	? QTN_AC_MGMT :	\
	WMM_AC_BE)

#define QTN_TID_COLLAPSE(_tid)	WMM_AC_TO_TID(TID_TO_WMM_AC(_tid))

#define AC_TO_QTN_QNUM(_ac)		\
	(((_ac) == WME_AC_BE) ? 1 :	\
	 ((_ac) == WME_AC_BK) ? 0 :	\
	  (_ac))

#define QTN_TID_MAP_UNUSED(_tid) ( \
	(_tid == QTN_TID_2) ? QTN_TID_BK : \
	(_tid == QTN_TID_3) ? QTN_TID_BE : \
	(_tid))

#define QTN_TID_MAP_80211(_tid) ( \
	(_tid == QTN_TID_2) ? QTN_TID_BK : \
	(_tid == QTN_TID_3) ? QTN_TID_BE : \
	(_tid == QTN_TID_WLAN) ? QTN_TID_VI : \
	(_tid == QTN_TID_MGMT) ? QTN_TID_VO : \
	(_tid))

#endif	/* _QTN_WMM_AC_H */
