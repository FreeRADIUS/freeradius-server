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

/** Resource pool management using slabs of memory
 *
 * @file src/lib/util/slab.h
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(slab_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/event.h>

/** conf_parser_t entries to populate user configurable slab values
 */
#define FR_SLAB_CONFIG_CONF_PARSER \
	{ FR_CONF_OFFSET("min", fr_slab_config_t, min_elements), .dflt = "10" }, \
	{ FR_CONF_OFFSET("max", fr_slab_config_t, max_elements), .dflt = "100" }, \
	{ FR_CONF_OFFSET("cleanup_interval", fr_slab_config_t, interval), .dflt = "30s" }, \

/** Tuneable parameters for slabs
 */
typedef struct { \
	unsigned int		elements_per_slab;	//!< Number of elements to allocate per slab.
	unsigned int		min_elements;		//!< Minimum number of elements to keep allocated.
	unsigned int		max_elements;		//!< Maximum number of elements to allocate using slabs.
	bool			at_max_fail;		//!< Should requests for additional elements fail when the
							///< number in use has reached max_elements.
	unsigned int		num_children;		//!< How many child allocations are expected off each element.
	size_t			child_pool_size;	//!< Size of pool space to be allocated to each element.
	fr_time_delta_t		interval;		//!< Interval between slab cleanup events being fired.
} fr_slab_config_t;

/** Define type specific wrapper structs for slabs and slab elements
 *
 * @note This macro should be used inside the header for the area of code
 * which will use the type specific slabs.
 *
 * The top level structure is the slab_list.  Slab elements are reserved
 * from this list.  One or more slabs are created as children of the slab_list
 * each of which consist of a number of elements.
 *
 * Within the slab_list there are two dlists which hold the slabs.  Slabs in
 * the `reserved` list have all their elements in use.  Slabs in the `avail`
 * list have elements available to reserve.
 *
 * Allocation of new elements can cause an allocation callback to be invoked
 * if elements need initialisation.
 *
 * @param[in] _name	to use in type specific structures.
 * @param[in] _type	of structure which will be held in the slab elements.
 */
#define FR_SLAB_TYPES(_name, _type) \
	FR_DLIST_TYPES(_name ## _slab) \
	FR_DLIST_TYPES(_name ## _slab_element) \
\
	typedef int (*_type ## _slab_free_t)(_type *elem, void *uctx); \
	typedef int (*_type ## _slab_alloc_t)(_type *elem, void *uctx); \
	typedef int (*_type ## _slab_reserve_t)(_type *elem, void *uctx); \
\
	typedef struct { \
		FR_DLIST_HEAD(_name ## _slab)		reserved; \
		FR_DLIST_HEAD(_name ## _slab)		avail; \
		fr_event_list_t				*el; \
		fr_timer_t				*ev; \
		fr_slab_config_t			config; \
		unsigned int				in_use; \
		unsigned int				high_water_mark; \
		_type ## _slab_alloc_t			alloc; \
		_type ## _slab_reserve_t		reserve; \
		void					*uctx; \
		bool					release_reset; \
		bool					reserve_mru; \
	} _name ## _slab_list_t; \
\
	typedef struct { \
		FR_DLIST_ENTRY(_name ## _slab)		entry; \
		_name ## _slab_list_t			*list; \
		TALLOC_CTX				*pool; \
		FR_DLIST_HEAD(_name ## _slab_element)	reserved; \
		FR_DLIST_HEAD(_name ## _slab_element)	avail; \
	} _name ## _slab_t; \
\
	typedef struct { \
		_type					elem; \
		FR_DLIST_ENTRY(_name ## _slab_element)	entry; \
		bool					in_use; \
		_name ## _slab_t 			*slab; \
		_type ## _slab_free_t 			free; \
		void					*uctx; \
	} _name ## _slab_element_t;

/** Define type specific wrapper functions for slabs and slab elements
 *
 * @note This macro should be used inside the source file that will use
 * the type specific functions.
 *
 * @param[in] _name	used in type specific structures.
 * @param[in] _type	of structure returned by the reserve function.
 */
#define FR_SLAB_FUNCS(_name, _type) \
	FR_DLIST_FUNCS(_name ## _slab, _name ## _slab_t, entry) \
	FR_DLIST_FUNCS(_name ## _slab_element, _name ## _slab_element_t, entry) \
\
DIAG_OFF(unused-function) \
	/** Timer event for freeing unused slabs \
	 * \
	 * Called periodically to clear up slab allocations. \
	 * Slabs where all elements are not in use will be freed, \
	 * up to half of the element count between the high water mark \
	 * and the current number in use. \
	 */ \
	 static void _ ## _name ## _slab_cleanup(fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx) \
	 { \
	 	_name ## _slab_list_t	*slab_list = talloc_get_type_abort(uctx, _name ## _slab_list_t); \
		_name ## _slab_t		*slab = NULL, *next_slab = NULL; \
		unsigned int			to_clear, cleared = 0; \
		to_clear = (slab_list->high_water_mark - slab_list->in_use) / 2; \
		if ((slab_list->in_use + to_clear) < slab_list->config.min_elements) \
			to_clear = slab_list->high_water_mark - slab_list->config.min_elements; \
		if (to_clear < slab_list->config.elements_per_slab) goto finish; \
		slab = _name ## _slab_head(&slab_list->avail); \
		while (slab) { \
			next_slab = _name ## _slab_next(&slab_list->avail, slab); \
			if (_name ## _slab_element_num_elements(&slab->reserved) > 0) goto next; \
			_name ## _slab_remove(&slab_list->avail, slab); \
			cleared += _name ## _slab_element_num_elements(&slab->avail); \
			to_clear -= _name ## _slab_element_num_elements(&slab->avail); \
			_name ## _slab_element_talloc_free(&slab->avail); \
			talloc_free(slab); \
			if (to_clear < slab_list->config.elements_per_slab) break; \
		next: \
			slab = next_slab; \
		} \
		slab_list->high_water_mark -= cleared; \
	finish: \
		(void) fr_timer_in(slab_list, tl, &slab_list->ev, slab_list->config.interval, false, \
				   _ ## _name ## _slab_cleanup, slab_list); \
	 } \
\
	/** Allocate a slab list to manage slabs of allocated memory \
	 * \
	 * @param[in] ctx		in which to allocate the slab list. \
	 * @param[in] el		Event list in which to run clean up function. \
	 * @param[in] config		Slab config parameters. \
	 * @param[in] alloc		Optional callback to use when allocating new elements. \
	 * @param[in] reserve		Optional callback run on element reserving. \
	 * @param[in] uctx		to pass to callbacks. \
	 * @param[in] release_reset	On release: free talloc children, zero element memory. \
	 *				Use when elements may accumulate allocations that should not persist. \
	 * @param[in] reserve_mru	If true, the most recently used element will be returned when an element is reserved. \
	 * @return \
	 *	- A new slab. \
	 *	- NULL on error. \
	 */ \
	static inline _name ## _slab_list_t *_name ## _slab_list_alloc(TALLOC_CTX *ctx, \
								       fr_event_list_t *el, \
								       fr_slab_config_t const *config, \
								       _type ## _slab_alloc_t alloc, \
								       _type ## _slab_reserve_t reserve, \
								       void *uctx, \
								       bool release_reset, \
								       bool reserve_mru) \
	{ \
		_name ## _slab_list_t *slab; \
		MEM(slab = talloc_zero(ctx, _name ## _slab_list_t)); \
		slab->el = el; \
		slab->config = *config; \
		if (slab->config.elements_per_slab == 0) { \
			slab->config.elements_per_slab = (config->min_elements ? config->min_elements : 1); \
		} \
		slab->alloc = alloc; \
		slab->reserve = reserve; \
		slab->uctx = uctx; \
		slab->release_reset = release_reset; \
		slab->reserve_mru = reserve_mru; \
		_name ## _slab_init(&slab->reserved); \
		_name ## _slab_init(&slab->avail); \
		if (el) { \
			if (unlikely(fr_timer_in(slab, el->tl, &slab->ev, config->interval, false, _ ## _name ## _slab_cleanup, slab) < 0)) { \
				talloc_free(slab); \
				return NULL; \
			}; \
		} \
		return slab; \
	} \
\
	/** Callback for talloc freeing a slab element \
	 * \
	 * Ensure that the element reset and custom destructor is called even if \
	 * the element is not released before being freed. \
	 * Also ensure the element is removed from the relevant list. \
	 */ \
	static int _ ## _type ## _element_free(_name ## _slab_element_t *element) \
	{ \
		_name ## _slab_t	*slab; \
		if (element->in_use && element->free) element->free(( _type *)element, element->uctx); \
		if (!element->slab) return 0; \
		slab = element->slab; \
		if (element->in_use) { \
			_name ## _slab_element_remove(&slab->reserved, element); \
		} else { \
			_name ## _slab_element_remove(&slab->avail, element); \
		} \
		return 0; \
	} \
\
	/** Reserve a slab element \
	 * \
	 * If there is not a free slab element already allocated, \
	 * a new slab will be allocated, until the the max_elements limit \
	 * of elements have been created. \
	 * \
	 * @param[in] slab_list		to reserve an element from. \
	 * @return a slab element. \
	 */ \
	static inline CC_HINT(nonnull) _type *_name ## _slab_reserve(_name ## _slab_list_t *slab_list) \
	{ \
		_name ## _slab_t		*slab; \
		_name ## _slab_element_t	*element = NULL; \
\
		slab = slab_list->reserve_mru ? _name ## _slab_tail(&slab_list->avail) : \
						_name ## _slab_head(&slab_list->avail); \
		if (!slab && ((_name ## _slab_num_elements(&slab_list->reserved) * \
			       slab_list->config.elements_per_slab) < slab_list->config.max_elements)) { \
			_name ## _slab_element_t *new_element; \
			unsigned int count, elems; \
			size_t elem_size; \
			elems = slab_list->config.elements_per_slab * (1 + slab_list->config.num_children); \
			elem_size = slab_list->config.elements_per_slab * (sizeof(_name ## _slab_element_t) + \
									   slab_list->config.child_pool_size); \
			MEM(slab = talloc_zero_pooled_object(slab_list, _name ## _slab_t, elems, elem_size)); \
			_name ## _slab_element_init(&slab->avail); \
			_name ## _slab_element_init(&slab->reserved); \
			_name ## _slab_insert_head(&slab_list->avail, slab); \
			slab->list = slab_list; \
			for (count = 0; count < slab_list->config.elements_per_slab; count++) { \
				if (slab_list->config.num_children > 0) { \
					MEM(new_element = talloc_zero_pooled_object(slab, _name ## _slab_element_t, \
										    slab_list->config.num_children, \
										    slab_list->config.child_pool_size)); \
				} else { \
					MEM(new_element = talloc_zero(slab, _name ## _slab_element_t)); \
				} \
				talloc_set_type(new_element, _type); \
				talloc_set_destructor(new_element, _ ## _type ## _element_free); \
				_name ## _slab_element_insert_tail(&slab->avail, new_element); \
				new_element->slab = slab; \
			} \
			/* Initialisation of new elements done after allocation to ensure \
			 * are all allocated from the pool.  Without this, any talloc done \
			 * by the callback may take memory from the pool. \
			 * Any elements which fail to initialise are freed immediately. */ \
			if (slab_list->alloc) { \
				_name ## _slab_element_t *prev = NULL; \
				new_element = NULL; \
				while ((new_element = _name ## _slab_element_next(&slab->avail, new_element))) { \
					if (slab_list->alloc((_type *)new_element, slab_list->uctx) < 0) { \
						prev = _name ## _slab_element_remove(&slab->avail, new_element); \
						talloc_free(new_element); \
						new_element = prev; \
						continue; \
					} \
				} \
			} \
			slab_list->high_water_mark += _name ## _slab_element_num_elements(&slab->avail); \
		} \
		if (!slab && slab_list->config.at_max_fail) return NULL; \
		if (slab) element = slab_list->reserve_mru ? _name ## _slab_element_pop_tail(&slab->avail) : \
							     _name ## _slab_element_pop_head(&slab->avail); \
		if (element) { \
			_name ## _slab_element_insert_tail(&slab->reserved, element); \
			if (_name ## _slab_element_num_elements(&slab->avail) == 0) { \
				_name ## _slab_remove(&slab_list->avail, slab); \
				_name ## _slab_insert_tail(&slab_list->reserved, slab); \
			} \
			element->in_use = true; \
			slab_list->in_use++; \
		} else { \
			MEM(element = talloc_zero(slab_list, _name ## _slab_element_t)); \
			talloc_set_type(element, _type); \
			talloc_set_destructor(element, _ ## _type ## _element_free); \
			if (slab_list->alloc) slab_list->alloc((_type *)element, slab_list->uctx); \
		} \
		if (slab_list->reserve) slab_list->reserve((_type *)element, slab_list->uctx); \
		return (_type *)element; \
	} \
\
	/** Set a function to be called when a slab element is released \
	 * \
	 * @param[in] elem	Element for which the routine should be set. \
	 * @param[in] func	Function to attach. \
	 * @param[in] uctx	to be passed to func. \
	 */ \
	static inline CC_HINT(nonnull(1,2)) void _name ## _slab_element_set_destructor(_type *elem, _type ## _slab_free_t func, void *uctx) \
	{ \
		_name ## _slab_element_t	*element = (_name ## _slab_element_t *)elem; \
		element->free = func; \
		element->uctx = uctx; \
	} \
\
	/** Release a slab element \
	 * \
	 * If the element was allocated from a slab then it is returned \
	 * to the list of available elements.  Otherwise it is talloc freed. \
	 * \
	 * @param[in] elem	to release. \
	 */ \
	static inline CC_HINT(nonnull) void _name ## _slab_release(_type *elem) \
	{ \
		_name ## _slab_element_t *element = (_name ## _slab_element_t *)elem; \
		_name ## _slab_t *slab = element->slab; \
		if (element->free) element->free(elem, element->uctx); \
		if (slab) { \
			_name ## _slab_list_t	*slab_list; \
			slab_list = slab->list; \
			_name ## _slab_element_remove(&slab->reserved, element); \
			if (slab_list->release_reset){ \
				talloc_free_children(element); \
				memset(&element->elem, 0, sizeof(_type)); \
				element->free = NULL; \
				element->uctx = NULL; \
			} \
			_name ## _slab_element_insert_tail(&slab->avail, element); \
			if (_name ## _slab_element_num_elements(&slab->avail) == 1) { \
				_name ## _slab_remove(&slab_list->reserved, slab); \
				_name ## _slab_insert_tail(&slab_list->avail, slab); \
			} \
			slab_list->in_use--; \
			element->in_use = false; \
			return; \
		} \
		talloc_free(element); \
	} \
\
	static inline CC_HINT(nonnull) unsigned int _name ## _slab_num_elements_used(_name ## _slab_list_t *slab_list) \
	{ \
		return slab_list->in_use; \
	} \
\
	static inline CC_HINT(nonnull) unsigned int _name ## _slab_num_allocated(_name ## _slab_list_t *slab_list) \
	{ \
		return _name ## _slab_num_elements(&slab_list->reserved) + \
		       _name ## _slab_num_elements(&slab_list->avail); \
	} \
DIAG_ON(unused-function)

#ifdef __cplusplus
}
#endif
