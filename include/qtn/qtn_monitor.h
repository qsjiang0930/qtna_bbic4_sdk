/*
 * Copyright (c) 2016 Quantenna Communications, Inc.
 * All rights reserved.
 */
#ifndef __QTN_MONITOR_H__
#define __QTN_MONITOR_H__

#if defined(MUC_BUILD)

struct qtn_softc;
struct qtn_hal_rxstatus;

struct qtn_monitor_regs {
	uint32_t rx_csr_reg;
	uint32_t rx_cntl_allow_reg;
};

void qtn_monitor_mode_attach(struct qtn_softc *sc);
void qtn_monitor_mode_detach(struct qtn_softc *sc);
void qtn_monitor_mode_setup(struct qtn_softc *sc, uint32_t value);

#define MONITOR_STATE_ON 1
#define MONITOR_STATE_OFF 0

#endif	/* defined(MUC_BUILD) */

#define MONITOR_DEFAULT_ON_PERIOD	10
#define MONITOR_MIN_ON_PERIOD		1
#define MONITOR_MAX_ON_PERIOD		99
#define MONITOR_DEFAULT_CYCLE_PERIOD	1000
#define MONITOR_MIN_CYCLE_PERIOD	100
#define MONITOR_MAX_CYCLE_PERIOD	5000

#define MONITOR_ENABLE_MASK		0x00000001
#define MONITOR_ENABLE_SHIFT		0
#define MONITOR_MAKE_ENABLE(val)	(((val) << MONITOR_ENABLE_SHIFT) & MONITOR_ENABLE_MASK)
#define MONITOR_GET_ENABLE(val)		(((val) & MONITOR_ENABLE_MASK) >> MONITOR_ENABLE_SHIFT)

#define MONITOR_ABS_MASK		0x00000002
#define MONITOR_ABS_SHIFT		1
#define MONITOR_MAKE_ABS(val)		(((val) << MONITOR_ABS_SHIFT) & MONITOR_ABS_MASK)
#define MONITOR_GET_ABS(val)		(((val) & MONITOR_ABS_MASK) >> MONITOR_ABS_SHIFT)

#define MONITOR_ON_PERIOD_MASK		0x0001FFFC
#define MONITOR_ON_PERIOD_SHIFT		2
#define MONITOR_MAKE_ON_PERIOD(val)	(((val) << MONITOR_ON_PERIOD_SHIFT) & MONITOR_ON_PERIOD_MASK)
#define MONITOR_GET_ON_PERIOD(val)	(((val) & MONITOR_ON_PERIOD_MASK) >> MONITOR_ON_PERIOD_SHIFT)

#define MONITOR_CYCLE_PERIOD_MASK	0xFFFE0000
#define MONITOR_CYCLE_PERIOD_SHIFT	17
#define MONITOR_MAKE_CYCLE_PERIOD(val)	(((val) << MONITOR_CYCLE_PERIOD_SHIFT) & MONITOR_CYCLE_PERIOD_MASK)
#define MONITOR_GET_CYCLE_PERIOD(val)	(((val) & MONITOR_CYCLE_PERIOD_MASK) >> MONITOR_CYCLE_PERIOD_SHIFT)

#define MONITOR_DEFAULT_CONFIG		(\
			MONITOR_MAKE_CYCLE_PERIOD(MONITOR_DEFAULT_CYCLE_PERIOD) | \
			MONITOR_MAKE_ON_PERIOD(MONITOR_DEFAULT_ON_PERIOD))

#define IEEE80211_NAC_PERCENT_TO_INT	100
#endif /* __QTN_MONITOR_H__ */

