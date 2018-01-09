#ifndef _UTIL_BUFFER_H_
#define _UTIL_BUFFER_H_

#include <stddef.h>

/**
 * A poor man's vector.
 */
typedef struct dynamic_buffer_t
{
	char *buffer;
	size_t size;
} dynamic_buffer_t;

/**
 * Initializes the buffer's members.
 */
void dynamic_buffer_init(dynamic_buffer_t *this);

/**
 * Free/cleanup the buffer's members.
 */
void dynamic_buffer_destroy(dynamic_buffer_t *this);

/**
 * Writes from source into our buffer.
 * Grows to fit the incoming write.
 */
void dynamic_buffer_write(dynamic_buffer_t *this, const void *buffer, size_t size);

#endif // _UTIL_BUFFER_H_
