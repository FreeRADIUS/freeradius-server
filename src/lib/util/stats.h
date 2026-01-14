#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/util/stats.h
 * @brief Structures and functions for statistics.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(stats_h, "$Id$")

#include <freeradius-devel/util/pair.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Link a struct entry to an autoloaded #fr_dict_attr_t
 *
 */
typedef struct {
	fr_dict_attr_t const	**da_p;		//!< point to the autoload definition of the DA for this field
	fr_type_t		type;		//!< cached for locality and simplicity
	size_t			offset;		//!< from the start of the struct
	size_t			size;		//!< size of this field
} fr_stats_link_entry_t;

typedef struct {
	char const		*name;		//!< name of the stats structure
	fr_dict_attr_t const	**root_p;	//!< point to the autoload definition of the DA for this structure
	char const		*mib;		//!< MIB root
	size_t			size;		//!< overall size of the structure
	size_t			num_elements;	//!< number of elements in the table.  Note no "NULL" terminator
	fr_stats_link_entry_t	entry[];	//!< the field entries, in offset order
} fr_stats_link_t;

/**  Common header for all statistics instances
 *
 *	def	pointer to the linking definition of the structure for this instance
 *
 *	@todo - if we need additional tracking data (rb trees, dlists, etc.), they can go here.
 */
#define STATS_HEADER_COMMON \
	fr_stats_link_t const	*def
	
/** Generic statistics structure
 *
 */
typedef struct {
	STATS_HEADER_COMMON;			//!< common header

	uint8_t			stats[];	//!< generic statistics data
} fr_stats_instance_t;

/** Iterator for a statistics structure.
 *
 *  This is used internally, and there's no real need for code outside of the statistics library to use it.
 */
typedef struct {
	fr_stats_instance_t const *inst;
	unsigned int		  current;
} fr_stats_iter_t;


/** Macro to define a typedef for a particular instance of statistics
 *
 *  Defines fr_stats_name_instance_t which contains an instance of the statistics for fr_stats_name_t, and
 *  which points to the linking structure fr_stats_link_name_t.
 *
 *  Note that nothing needs to refer to the base statistics structure: fr_stats_name_t.  All of that is
 *  wrapped in an instance definition.
 *
 *  This is used internally, and there's no real need for code outside of the statistics library to use it.
 */
#define FR_STATS_TYPEDEF(_name) \
	typedef struct {		\
		STATS_HEADER_COMMON;	\
		fr_stats_ ## _name ## _t	stats;	 \
	} fr_stats_ ## _name ## _instance_t

/** Macro used when referencing a linking structure
 *
 *  .def = FR_STATS_LINK_NAME(radius_auth_serv),
 *
 *  This is used internally, and there's no real need for code outside of the statistics library to use it.
 */
#define FR_STATS_LINK_NAME(_name) fr_stats_link_ ## _name ## _t

/** Macro used when declaring a variable which contains an instance of the statistics
 *
 *  Defines "fr_stats_name_instance_t var", which can be used in a structure
 *
 *  Code which needs to use some statistics can use this macro to declare a variable which contains stats for
 *  the local module / etc.
 */
#define FR_STATS_ENTRY_DECL(_name, _var) fr_stats_ ## _name ## _instance_t _var

/** Macro used when initializing a variable which contains an instance of the statistics
 *
 *  var = .... initializer for the stats instance ...
 *
 *  Code which needs to use some statistics can use this macro to initialize a variable which contains stats
 *  for the local module / etc.
 */
#define FR_STATS_ENTRY_INIT(_name, _var, _mib)		\
	_var = (fr_stats_ ## _name ## _instance_t) {	\
		.def = fr_stats_link_ ## _name ## _t,	\
		.mib = _mib,				\
		fr_stats_ ## _name ## _t stats = {},	\
	       }


/** Macro used to increment one field in the statistics structure
 *
 *  Code which needs to update some statistics can use this macro to increment a variable which contains
 *  stats for the local module / etc.
 */
#define FR_STATS_INC(_var, _field) ((_var)->stats.(_field))++

/** Macro used to reference a field in the statistics structure
 *
 *  Code which needs to mangle a field of the statistics can use this macro to get the correct field name.
 */
#define FR_STATS_FIELD(_var, _field) (_var)->stats.(_field)

int	fr_stats_to_pairs(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_stats_instance_t const *in) CC_HINT(nonnull);
int	fr_stats_from_pairs(TALLOC_CTX *ctx, fr_stats_instance_t *out, fr_pair_list_t *in) CC_HINT(nonnull);
int	fr_stats_merge(fr_stats_instance_t *out, fr_stats_instance_t const *in) CC_HINT(nonnull);

void	fr_stats_iter_init(fr_stats_instance_t const *in, fr_stats_iter_t *iter) CC_HINT(nonnull);
bool	fr_stats_iter_next(fr_stats_iter_t *iter) CC_HINT(nonnull);
int	fr_stats_iter_to_value_box(TALLOC_CTX *ctx, fr_value_box_t **out, fr_stats_iter_t *iter) CC_HINT(nonnull);
int	fr_stats_index_to_value_box(TALLOC_CTX *ctx, fr_value_box_t **out, fr_stats_instance_t const *in, unsigned int index) CC_HINT(nonnull);


#ifdef __cplusplus
}
#endif
