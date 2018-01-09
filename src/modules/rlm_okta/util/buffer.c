#include <stdlib.h>
#include <string.h>

#include "buffer.h"

#include <stdio.h>

/**
 * Reallocs the buffer to accommodate the incoming payload.
 */
static void size_up(dynamic_buffer_t *this, size_t num_bytes_requested)
{
	this->size += num_bytes_requested + 1;
	this->buffer = realloc(this->buffer, this->size);
}

/**
 * Initializes the buffer's members.
 */
void dynamic_buffer_init(dynamic_buffer_t *this)
{
	this->buffer = malloc(1);
	this->size = 0;
}

/**
 * Free/cleanup the buffer's members.
 */
void dynamic_buffer_destroy(dynamic_buffer_t *this)
{
	free(this->buffer);
	this->buffer = NULL;
	this->size = 0;
}

/**
 * Writes from source into our buffer.
 * Grows to fit the incoming write.
 */
void dynamic_buffer_write(dynamic_buffer_t *this, const void *source, size_t size)
{
	size_t orig = this->size;
	size_up(this, size);
	memcpy(this->buffer + orig, source, size);
}
