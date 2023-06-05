/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO Utils
 *
 * It includes some useful utilities for efficient implementation.
 */

#ifndef __DAO_UTIL_H__
#define __DAO_UTIL_H__

/**
 * @def DAO_FREE
 *
 * Free a pointer and assign to NULL
 *
 */
#define DAO_FREE(ptr)                                                                              \
	do {                                                                                       \
		free(ptr);                                                                         \
		ptr = NULL;                                                                        \
	} while (0)

/**
 * @def DAO_ROUNDUP
 *
 * Roundup x to be exact multiple of y
 */
#define DAO_ROUNDUP(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

/**
 * @def DAO_ROUNDDOWN
 *
 * Round-down x to be exact multiple of y
 */
#define DAO_ROUNDDOWN(x, y) ((x / y) * y)

/**
 * @def DAO_BIT
 *
 * Bit in unsigned long.
 */
#define DAO_BIT(nr) (1UL << (nr))

/**
 * @def DAO_BIT_ULL
 *
 * Bit in unsigned long long.
 */
#define DAO_BIT_ULL(nr) (1ULL << (nr))

/**
 * @def DAO_BITS_PER_LONG_LONG
 *
 * Bits in unsigned long long.
 */
#define DAO_BITS_PER_LONG_LONG (__SIZEOF_LONG_LONG__ * 8)

/**
 * @def DAO_GENMASK_ULL
 *
 * Unsigned long long bitmask with bits set between high and low positions.
 */
#define DAO_GENMASK_ULL(h, l) (((~0ULL) << (l)) & (~0ULL >> (DAO_BITS_PER_LONG_LONG - 1 - (h))))

/**
 * @def DAO_STATIC_ASSERT
 *
 * STATIC ASSERT API
 */
#define DAO_STATIC_ASSERT(s) _Static_assert(s, #s)

/**
 * @def DAO_TAILQ_FOREACH_SAFE
 *
 * This macro permits both remove and free var within the loop safely.
 */
#define DAO_TAILQ_FOREACH_SAFE(var, head, field, tvar)                                             \
	for ((var) = TAILQ_FIRST((head)); (var) && ((tvar) = TAILQ_NEXT((var), field), 1);         \
	     (var) = (tvar))

/**
 * Check if bit is set in a no
 *
 * Check if bit at given position is set for a given no.
 *
 * @param	n	Input number
 * @param	pos	Bit position
 */
static inline bool
dao_check_bit_is_set(int n, int pos)
{
	return (n & (1 << (pos - 1))) != 0;
}

/**
 * Derive HW function from its PCI BDF
 *
 * Derive the Hardware func component from its PCI BDF notation
 *
 * @param	pci_bdf		PCI BDF source string
 *
 * @retval	< 0		Failure
 *		> 0		Success: hw function value
 */

int dao_pci_bdf_to_hw_func(const char *pci_bdf);

/**
 * API to memcpy on volatile memory
 *
 * @param d
 *    Destination location
 * @param s
 *    Source location
 * @param l
 *    Length in bytes.
 * @return
 *    Destination pointer on success.
 */
static inline volatile void *
dao_dev_memcpy(volatile void *d, const volatile void *s, size_t l)
{
	const volatile uint8_t *sb;
	volatile uint8_t *db;
	size_t i;

	if (!d || !s)
		return NULL;
	db = (volatile uint8_t *)d;
	sb = (const volatile uint8_t *)s;
	for (i = 0; i < l; i++)
		db[i] = sb[i];
	return d;
}

/**
 * API to memset on volatile memory
 *
 * @param d
 *    Destination location.
 * @param val
 *    Value to memset with.
 * @param l
 *    Length in bytes.
 */
static inline void
dao_dev_memset(volatile void *d, uint8_t val, size_t l)
{
	volatile uint8_t *db;
	size_t i = 0;

	if (!d || !l)
		return;
	db = (volatile uint8_t *)d;
	for (i = 0; i < l; i++)
		db[i] = val;
}

/**
 * API to zero on volatile memory
 *
 * @param d
 *    Destination location.
 * @param l
 *    Length in bytes.
 */
static inline void
dao_dev_memzero(volatile void *d, size_t l)
{
	volatile uint64_t *db;
	size_t i = 0;

	if (!d || !l || (l % 8))
		return;

	db = (volatile uint64_t *)d;
	for (i = 0; i < l; i++)
		db[i] = 0;
}
#endif /* __DAO_UTIL_H__ */
