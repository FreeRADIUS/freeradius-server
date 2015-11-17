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
#ifndef _DICT_H
#define _DICT_H

#include <freeradius-devel/libradius.h>

#ifdef WITH_VERIFY_PTR
#  define VERIFY_DA(_x)		fr_dict_verify(__FILE__,  __LINE__, _x)
#else
#  define VERIFY_DA(_x)		fr_assert(_x)
#endif

typedef struct attr_flags {
	unsigned int	is_root : 1;				//!< Is root of a dictionary.
	unsigned int 	is_unknown : 1;				//!< Attribute number or vendor is unknown.

	unsigned int	internal : 1;				//!< Internal attribute, should not be received
								//!< in protocol packets, should not be encoded.
	unsigned int	has_tag : 1;				//!< Tagged attribute.
	unsigned int	array : 1; 				//!< Pack multiples into 1 attr.
	unsigned int	has_value : 1;				//!< Has a value.
	unsigned int	has_value_alias : 1; 			//!< Has a value alias.

	unsigned int	wimax: 1;				//!< WiMAX format=1,1,c.

	unsigned int	concat : 1;				//!< concatenate multiple instances
	unsigned int	is_pointer : 1;				//!< data is a pointer

	unsigned int	virtual : 1;				//!< for dynamic expansion

	unsigned int	compare : 1;				//!< has a paircompare registered

	uint8_t		encrypt;      				//!< Ecryption method.
	uint8_t		length;
} ATTR_FLAGS;

/*
 *  Values of the encryption flags.
 */
#define FLAG_ENCRYPT_NONE	    (0)
#define FLAG_ENCRYPT_USER_PASSWORD   (1)
#define FLAG_ENCRYPT_TUNNEL_PASSWORD (2)
#define FLAG_ENCRYPT_ASCEND_SECRET   (3)

extern const FR_NAME_NUMBER dict_attr_types[];
extern const size_t dict_attr_sizes[PW_TYPE_MAX][2];

typedef struct dict_attr fr_dict_attr_t;

typedef struct fr_dict fr_dict_t;
extern fr_dict_t *fr_main_dict;

/** Dictionary attribute
 *
 */
struct dict_attr {
	unsigned int		vendor;				//!< Vendor that defines this attribute.
	unsigned int		attr;				//!< Attribute number.
	unsigned int		max_attr;			//!< Maximum attribute number for this parent.
	PW_TYPE			type;				//!< Value type.

	fr_dict_attr_t const	*parent;			//!< Immediate parent of this attribute.
	fr_dict_attr_t const	**children;			//!< Children of this attribute.
	fr_dict_attr_t const	*next;				//!< Next child in bin.

	unsigned int		depth;				//!< Depth of nesting for this attribute.

	ATTR_FLAGS		flags;				//!< Flags.
	char			name[1];			//!< Attribute name.
};

/** value of an enumerated attribute
 *
 */
typedef struct dict_value {
	fr_dict_attr_t const	*da;
	int			value;
	char			name[1];
} fr_dict_value_t;

/** dictionary vendor
 *
 */
typedef struct dict_vendor {
	unsigned int		vendorpec;
	size_t			type; 				//!< Length of type data
	size_t			length;				//!< Length of length data
	size_t			flags;
	char			name[1];
} fr_dict_vendor_t;

/*
 *	Dictionary functions.
 */
#define FR_DICT_VALUE_MAX_NAME_LEN (128)
#define FR_DICT_VENDOR_MAX_NAME_LEN (128)
#define FR_DICT_ATTR_MAX_NAME_LEN (128)
#define MAX_TLV_NEST (24)
#define MAX_TLV_STACK MAX_TLV_NEST + 5
#define FR_DICT_ATTR_SIZE sizeof(fr_dict_attr_t) + FR_DICT_ATTR_MAX_NAME_LEN

extern const int fr_dict_attr_allowed_chars[256];
int			fr_dict_valid_name(char const *name);

int			fr_dict_str_to_argv(char *str, char **argv, int max_argc);
fr_dict_attr_t const	*fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr);
fr_dict_attr_t const	*fr_dict_attr_child_by_da(fr_dict_attr_t const *parent, fr_dict_attr_t const *child);
ssize_t			fr_dict_str_to_oid(unsigned int *vendor, unsigned int *attr,
					   fr_dict_attr_t const **parent, char const *oid);
int			fr_dict_vendor_add(char const *name, unsigned int value);
int			fr_dict_attr_add(fr_dict_attr_t const *parent, char const *name, unsigned int vendor, int attr,
					 PW_TYPE type, ATTR_FLAGS flags);
int			fr_dict_value_add(char const *attrstr, char const *namestr, int value);

fr_dict_attr_t const	*fr_dict_root(fr_dict_t const *dict);
int			fr_dict_init(TALLOC_CTX *ctx, fr_dict_t **out,
				     char const *dir, char const *fn, char const *name);

int			fr_dict_read(fr_dict_t *dict, char const *dir, char const *filename);

void			fr_dict_attr_free(fr_dict_attr_t const **da);

int			fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t const **out,
							 fr_dict_attr_t const *parent, unsigned int vendor);
int			fr_dict_unknown_from_fields(fr_dict_attr_t *da, fr_dict_attr_t const *parent,
						    unsigned int vendor, unsigned int attr) CC_HINT(nonnull);
fr_dict_attr_t		*fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
						      unsigned int vendor, unsigned int attr) CC_HINT(nonnull);
int			fr_dict_unknown_from_oid(fr_dict_attr_t *vendor_da, fr_dict_attr_t *da,
						 fr_dict_attr_t const *parent, char const *name);
fr_dict_attr_t const	*fr_dict_unknown_afrom_oid(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, char const *name);
int			fr_dict_unknown_from_suboid(fr_dict_attr_t *vendor_da, fr_dict_attr_t *da,
						    fr_dict_attr_t const *parent, char const **name);

void			fr_dict_print(fr_dict_attr_t const *da, int depth);
fr_dict_attr_t const	*fr_dict_parent_common(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor);
fr_dict_attr_t const	*fr_dict_unknown_add(fr_dict_attr_t const *old);

fr_dict_attr_t const	*fr_dict_attr_by_num(unsigned int vendor, unsigned int attr);
fr_dict_attr_t const	*fr_dict_attr_by_name(char const *attr);
fr_dict_attr_t const	*fr_dict_attr_by_name_substr(char const **name);
fr_dict_attr_t const	*fr_dict_attr_by_type(unsigned int vendor, unsigned int attr, PW_TYPE type);
fr_dict_value_t		*fr_dict_value_by_da(fr_dict_attr_t const *da, int value);
fr_dict_value_t		*fr_dict_value_by_name(fr_dict_attr_t const *da, char const *val);
char const		*fr_dict_value_name_by_attr(fr_dict_attr_t const *da, int value);
int			fr_dict_vendor_by_name(char const *name);
fr_dict_vendor_t	*fr_dict_vendor_by_num(int vendor);
void			fr_dict_verify(char const *file, int line, fr_dict_attr_t const *da);
#endif /* _DICT_H */
