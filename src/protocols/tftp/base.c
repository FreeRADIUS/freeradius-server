/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file src/protocols/tftp/base.c
 * @brief TFTP protocol.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include "tftp.h"
#include "attrs.h"

static uint32_t instance_count = 0;

fr_dict_t const *dict_tftp;

extern fr_dict_autoload_t libfreeradius_tftp[];
fr_dict_autoload_t libfreeradius_tftp[] = {
	{ .out = &dict_tftp, .proto = "tftp" },
	{ NULL }
};

fr_dict_attr_t const *attr_tftp_block;
fr_dict_attr_t const *attr_tftp_block_size;
fr_dict_attr_t const *attr_tftp_data;
fr_dict_attr_t const *attr_tftp_error_code;
fr_dict_attr_t const *attr_tftp_error_message;
fr_dict_attr_t const *attr_tftp_filename;
fr_dict_attr_t const *attr_tftp_opcode;
fr_dict_attr_t const *attr_tftp_mode;

fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t libfreeradius_tftp_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_tftp_dict_attr[] = {
	{ .out = &attr_tftp_block, .name = "TFTP-Block", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_block_size, .name = "TFTP-Block-Size", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_data, .name = "TFTP-Data", .type = FR_TYPE_OCTETS, .dict = &dict_tftp },
	{ .out = &attr_tftp_error_code, .name = "TFTP-Error-Code", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_error_message, .name = "TFTP-Error-Message", .type = FR_TYPE_STRING, .dict = &dict_tftp },
	{ .out = &attr_tftp_filename, .name = "TFTP-Filename", .type = FR_TYPE_STRING, .dict = &dict_tftp },
	{ .out = &attr_tftp_opcode, .name = "TFTP-Opcode", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_mode, .name = "TFTP-Mode", .type = FR_TYPE_UINT8, .dict = &dict_tftp },

	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tftp },

	{ NULL }
};

char const *fr_tftp_codes[FR_TFTP_MAX_CODE] = {
	[FR_PACKET_TYPE_VALUE_READ_REQUEST] = "Read-Request",
	[FR_PACKET_TYPE_VALUE_WRITE_REQUEST] = "Write-Request",
	[FR_PACKET_TYPE_VALUE_DATA] = "Data",
	[FR_PACKET_TYPE_VALUE_ACKNOWLEDGEMENT] = "Acknowledgement",
	[FR_PACKET_TYPE_VALUE_ERROR] = "Error",
	[FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND] = "Do-Not-Respond"
};

char const *fr_tftp_error_codes[FR_TFTP_MAX_ERROR_CODE] = {
	[FR_TFTP_ERROR_CODE_VALUE_FILE_NOT_FOUND] = "File not found",
	[FR_TFTP_ERROR_CODE_VALUE_ACCESS_VIOLATION] = "Access violation",
	[FR_TFTP_ERROR_CODE_VALUE_DISK_FULL] = "Disk Full",
	[FR_TFTP_ERROR_CODE_VALUE_ILLEGAL_TFTP_OPERATION] = "Illegal TFTP operation",
	[FR_TFTP_ERROR_CODE_VALUE_UNKNOWN_TRANSFER_ID] = "Unknown transfer ID",
	[FR_TFTP_ERROR_CODE_VALUE_FILE_ALREADY_EXISTS] = "File already exists",
	[FR_TFTP_ERROR_CODE_VALUE_NO_SUCH_USER] = "No such user"
};

int fr_tftp_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_tftp) < 0) {
		fr_strerror_printf_push("Failed loading the 'tftp' dictionary");
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_tftp_dict_attr) < 0) {
		fr_strerror_printf("Failed loading the 'tftp' attributes");
		fr_dict_autofree(libfreeradius_tftp);
		return -1;
	}

	instance_count++;

	return 0;
}

void fr_tftp_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_tftp);
}
