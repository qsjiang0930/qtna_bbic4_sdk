/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 */
#ifndef QTN_HARDWARE_WAR_H
#define QTN_HARDWARE_WAR_H

RUBY_INLINE int qtn_hw_disable_amsdu(uint32_t ni_ver_hw)
{
	return ni_ver_hw <= HARDWARE_REVISION_RUBY_D;
}

RUBY_INLINE int qtn_hw_mod_bf_is_supported_in_5g(uint32_t hw_option)
{
	if (hw_option == HW_OPTION_BONDING_TOPAZ_QT952_2X2 ||
			hw_option == HW_OPTION_BONDING_TOPAZ_QV940)
		return 0;
	return 1;
}
#endif
