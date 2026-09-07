#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include <freeradius-devel/libradius.h>

static int check_integer64_to_signed(uint64_t value, int expected, bool success)
{
	value_data_t src = { .integer64 = value };
	value_data_t dst = { .sinteger = -1 };
	ssize_t rcode;

	rcode = value_data_cast(NULL, &dst, PW_TYPE_SIGNED, NULL,
				PW_TYPE_INTEGER64, NULL,
				&src, sizeof(src.integer64));

	if (success) {
		if (rcode != (ssize_t)sizeof(dst.sinteger)) return -1;
		if (dst.sinteger != expected) return -1;
		return 0;
	}

	if (rcode >= 0) return -1;

	/*
	 * Failed casts must not modify the destination.
	 */
	if (dst.sinteger != -1) return -1;

	return 0;
}

int main(void)
{
	if (check_integer64_to_signed(INT_MAX, INT_MAX, true) < 0) {
		return EXIT_FAILURE;
	}

	if (check_integer64_to_signed((uint64_t)INT_MAX + 1, 0, false) < 0) {
		return EXIT_FAILURE;
	}

	if (check_integer64_to_signed(UINT64_C(1) << 32, 0, false) < 0) {
		return EXIT_FAILURE;
	}

	if (check_integer64_to_signed(UINT64_MAX, 0, false) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
