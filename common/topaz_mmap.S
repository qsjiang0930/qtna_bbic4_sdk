/*
 * (C) Copyright 2010 Quantenna Communications Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#if defined(__linux__) && defined (__KERNEL__)
#if defined (DC_CTRL_FLUSH_STATUS)
	#define ARC_DC_FLUSH_STATUS_BIT	DC_CTRL_FLUSH_STATUS
#elif defined (BIT_DC_CTRL_FLUSH_STATUS)
	#define ARC_DC_FLUSH_STATUS_BIT	BIT_DC_CTRL_FLUSH_STATUS
#endif
#endif


topaz_unified_mmap:
	.globl topaz_unified_mmap
	/* Code must be position-independent! */

	/*
	* Flush and invalidate data cache.
	* Please make sure that instructions which touch
	* d-cache are NOT used until flipping is done.
	*/
	/* Set flush mode for invalidate operation */
	lr      r3, [ARC_REG_DC_CTRL]
	bset    r3, r3, 0x6
	sr      r3, [ARC_REG_DC_CTRL]
	/* Start invalidate operation */
	mov     r3, 0x1
	sr      r3, [ARC_REG_DC_IVDC]
	/* Check while cache invalidating will be finished */
dcache_flush_continue:
	lr      r3, [ARC_REG_DC_CTRL]
	and     r3, r3, ARC_DC_FLUSH_STATUS_BIT
	brne    r3, 0x0, dcache_flush_continue

	/* Prepare flipping.
	 * After code is finished, memory maps will change as follows:
	 *     Flip map:
	 *         SRAM 0x8000_0000 -> 0x8800_0000
	 *         DRAM 0x0         -> 0x8000_0000
	 *     Unified map:
	 *         SRAM 0x8000_0000 -> 0x9800_0000
	 *         DRAM 0x0         -> 0x8000_0000
	 */
	mov     r3, RUBY_SYS_CTL_BASE_ADDR_NOMAP
	mov     r4, RUBY_SYS_CTL_MMAP_REGVAL
	or      r4, r4, RUBY_SYS_CTL_REMAP(0x3)
	st.di   r4, [r3, RUBY_SYS_CTL_MASK - RUBY_SYS_CTL_BASE_ADDR]
	mov     r4, RUBY_SYS_CTL_MMAP_REGVAL

.align 32 /*ARC_ICACHE_LINE_LEN*/
	/* Do flipping.
	* Align to cache line to ensure we don't hit memory during following instructions.
	* Code must fit into 1 cache line (32 bytes).
	*/
	st.di   r4, [r3, RUBY_SYS_CTL_CTRL - RUBY_SYS_CTL_BASE_ADDR]
	ld.di   r4, [r3, RUBY_SYS_CTL_CTRL - RUBY_SYS_CTL_BASE_ADDR] /* read back to clear pipeline */
	sync
	j       boot_continue		/* jump to absolute addr in sram */
	/* Align to cache line so code occupy strictly 1 cache line. */
.align 32 /* ARC_ICACHE_LINE_LEN */

boot_continue:
	/* Finalize flipping. */
	mov     r4, 0x0
	st.di   r4, [r3, RUBY_SYS_CTL_MASK - RUBY_SYS_CTL_BASE_ADDR]

	/* Let's discard instruction cache.
	*/
	mov     r4, 0x1
	sr      r4, [ARC_REG_IC_IVIC] /* invalidate i-cache */
	lr      r4, [ARC_REG_IC_CTRL] /* read will be not completed until i-cache is invalidated */

	/* Done. We are now sitting in different addresses. */
	b	ruby_boot

