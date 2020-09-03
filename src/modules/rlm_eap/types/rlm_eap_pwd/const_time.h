/*
 * Helper functions for constant time operations
 * Copyright (c) 2019, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * These helper functions can be used to implement logic that needs to minimize
 * externally visible differences in execution path by avoiding use of branches,
 * avoiding early termination or other time differences, and forcing same memory
 * access pattern regardless of values.
 */

#ifndef CONST_TIME_H
#define CONST_TIME_H


#if defined(__clang__)
#define NO_UBSAN_UINT_OVERFLOW                                        \
	__attribute__((no_sanitize("unsigned-integer-overflow")))
#else
#define NO_UBSAN_UINT_OVERFLOW
#endif

/**
 * const_time_fill_msb - Fill all bits with MSB value
 * @param	val Input value
 * @return	Value with all the bits set to the MSB of the input val
 */
static inline unsigned int const_time_fill_msb(unsigned int val)
{
	/* Move the MSB to LSB and multiple by -1 to fill in all bits. */
	return (val >> (sizeof(val) * 8 - 1)) * ~0U;
}


/* @return	-1 if val is zero; 0 if val is not zero */
static inline unsigned int const_time_is_zero(unsigned int val)
	NO_UBSAN_UINT_OVERFLOW
{
	/* Set MSB to 1 for 0 and fill rest of bits with the MSB value */
	return const_time_fill_msb(~val & (val - 1));
}


/* @return	-1 if a == b; 0 if a != b */
static inline unsigned int const_time_eq(unsigned int a, unsigned int b)
{
	return const_time_is_zero(a ^ b);
}


/* @return	-1 if a == b; 0 if a != b */
static inline unsigned char const_time_eq_u8(unsigned int a, unsigned int b)
{
	return (unsigned char) const_time_eq(a, b);
}


/**
 * const_time_eq_bin - Constant time memory comparison
 * @param	a First buffer to compare
 * @param	b Second buffer to compare
 * @param	len Number of octets to compare
 * @return	-1 if buffers are equal, 0 if not
 *
 * This function is meant for comparing passwords or hash values where
 * difference in execution time or memory access pattern could provide external
 * observer information about the location of the difference in the memory
 * buffers. The return value does not behave like memcmp(), i.e.,
 * const_time_eq_bin() cannot be used to sort items into a defined order. Unlike
 * memcmp(), the execution time of const_time_eq_bin() does not depend on the
 * contents of the compared memory buffers, but only on the total compared
 * length.
 */
static inline unsigned int const_time_eq_bin(const void *a, const void *b,
					     size_t len)
{
	const unsigned char *aa = a;
	const unsigned char *bb = b;
	size_t i;
	unsigned char res = 0;

	for (i = 0; i < len; i++)
		res |= aa[i] ^ bb[i];

	return const_time_is_zero(res);
}


/**
 * const_time_select - Constant time unsigned int selection
 * @param	mask 0 (false) or -1 (true) to identify which value to select
 * @param	true_val Value to select for the true case
 * @param	false_val Value to select for the false case
 * @return	true_val if mask == -1, false_val if mask == 0
 */
static inline unsigned int const_time_select(unsigned int mask,
					     unsigned int true_val,
					     unsigned int false_val)
{
	return (mask & true_val) | (~mask & false_val);
}


/**
 * const_time_select_int - Constant time int selection
 * @param	mask 0 (false) or -1 (true) to identify which value to select
 * @param	true_val Value to select for the true case
 * @param	false_val Value to select for the false case
 * @return	true_val if mask == -1, false_val if mask == 0
 */
static inline int const_time_select_int(unsigned int mask, int true_val,
					int false_val)
{
	return (int) const_time_select(mask, (unsigned int) true_val,
				       (unsigned int) false_val);
}


/**
 * const_time_select_u8 - Constant time u8 selection
 * @param	mask 0 (false) or -1 (true) to identify which value to select
 * @param	true_val Value to select for the true case
 * @param	false_val Value to select for the false case
 * @return	true_val if mask == -1, false_val if mask == 0
 */
static inline unsigned char const_time_select_u8(unsigned char mask, unsigned char true_val, unsigned char false_val)
{
	return (unsigned char) const_time_select(mask, true_val, false_val);
}


/**
 * const_time_select_s8 - Constant time s8 selection
 * @param	mask 0 (false) or -1 (true) to identify which value to select
 * @param	true_val Value to select for the true case
 * @param	false_val Value to select for the false case
 * @return	true_val if mask == -1, false_val if mask == 0
 */
static inline char const_time_select_s8(char mask, char true_val, char false_val)
{
	return (char) const_time_select(mask, (unsigned int) true_val,
				      (unsigned int) false_val);
}


/**
 * const_time_select_bin - Constant time binary buffer selection copy
 * @param	mask 0 (false) or -1 (true) to identify which value to copy
 * @param	true_val Buffer to copy for the true case
 * @param	false_val Buffer to copy for the false case
 * @param	len Number of octets to copy
 * @param	dst Destination buffer for the copy
 *
 * This function copies the specified buffer into the destination buffer using
 * operations with identical memory access pattern regardless of which buffer
 * is being copied.
 */
static inline void const_time_select_bin(unsigned char mask, const unsigned char *true_val,
					 const unsigned char *false_val, size_t len,
					 unsigned char *dst)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = const_time_select_u8(mask, true_val[i], false_val[i]);
}


static inline int const_time_memcmp(const void *a, const void *b, size_t len)
{
	const unsigned char *aa = a;
	const unsigned char *bb = b;
	int diff, res = 0;
	unsigned int mask;

	if (len == 0)
		return 0;
	do {
		len--;
		diff = (int) aa[len] - (int) bb[len];
		mask = const_time_is_zero((unsigned int) diff);
		res = const_time_select_int(mask, res, diff);
	} while (len);

	return res;
}

#endif /* CONST_TIME_H */
