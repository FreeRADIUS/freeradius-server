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
 * @file io/coord.h
 * @brief Coordination thread management
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(coord_h, "$Id$")

#include <freeradius-devel/io/control.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/module_ctx.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/semaphore.h>

typedef struct fr_coord_reg_s fr_coord_reg_t;

typedef struct fr_coord_s fr_coord_t;
typedef struct fr_coord_worker_s fr_coord_worker_t;

typedef	void (*fr_coord_cb_t)(fr_coord_t *coord, uint32_t worker_id, fr_dbuff_t *dbuff, fr_time_t now, void *uctx);
typedef void (*fr_coord_worker_cb_t)(fr_coord_worker_t *cw, fr_dbuff_t *dbuff, fr_time_t now, void *uctx);

typedef struct {
	char const			*name;
	fr_coord_cb_t			callback;
	void				*uctx;
} fr_coord_cb_reg_t;

typedef struct {
	char const			*name;
	fr_coord_worker_cb_t		callback;
	void				*uctx;
} fr_coord_worker_cb_reg_t;

#define FR_COORD_CALLBACK_TERMINATOR 	{ .callback = NULL }

typedef struct {
	char const			*name;			//!< Name for this coordinator.
	fr_coord_cb_reg_t		*inbound_cb;		//!< Callbacks for worker -> coordinator messages.
	fr_coord_worker_cb_reg_t	*outbound_cb;		//!< Callbacks for coordinator -> worker messages.
	CONF_SECTION			*cs;			//!< Module conf section.
	char const			*module_name;		//!< Name of module for this coordinator.
	size_t				inbound_rb_size;	//!< Initial ring buffer size for worker -> coordinator
								///< data.  Defaults to 4096 if not set.
	size_t				outbound_rb_size;	//!< Initial ring buffer size for coordinator -> worker
								///< data. Defaults to 4096 of not set.
	fr_time_delta_t			max_request_time;	//!< Maximum time for coordinator request processing.
								///< Defaults to main config max request time.
} fr_coord_reg_ctx_t;

typedef struct {
	fr_coord_t			*coord;
	void				*uctx;
} fr_coord_to_worker_ctx_t;

typedef struct {
	fr_coord_worker_t		*cw;
	void				*uctx;
} fr_worker_to_coord_ctx_t;

fr_coord_reg_t	*fr_coord_register(TALLOC_CTX *ctx, fr_coord_reg_ctx_t *reg_ctx);

void		fr_coord_deregister(fr_coord_reg_t *coord_reg);

int		fr_coord_start(uint32_t num_workers, sem_t *sem);

int		fr_coords_create(TALLOC_CTX *ctx, fr_event_list_t *el);

int		fr_coord_pre_event_insert(fr_event_list_t *el);

int		fr_coord_post_event_insert(fr_event_list_t *el);

void		fr_coords_destroy(void);

fr_coord_worker_t	*fr_coord_attach(TALLOC_CTX *ctx, fr_event_list_t *el, fr_coord_reg_t *coord_reg);
int		fr_coord_detach(fr_coord_worker_t *cw);

int		fr_coord_to_worker_send(fr_coord_t *coord, uint32_t worker_id, uint32_t cb_id, fr_dbuff_t *dbuff);

int		fr_coord_to_worker_broadcast(fr_coord_t *coord, uint32_t cb_id, fr_dbuff_t *dbuff);

int		fr_worker_to_coord_send(fr_coord_worker_t *cw, uint32_t cb_id, fr_dbuff_t *dbuff);

module_instance_t const *fr_coord_process_module(fr_coord_t *coord);
