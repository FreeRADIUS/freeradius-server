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

/** State machine functions
 *
 * @file src/lib/util/machine.h
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(machine_h, "$Id$")

#include <freeradius-devel/util/dcursor.h>

typedef struct fr_machine_state_s fr_machine_state_t;

typedef struct fr_machine_s fr_machine_t;

typedef void (*fr_machine_func_t)(fr_machine_t *m, void *uctx);

typedef int (*fr_machine_process_t)(fr_machine_t *m, void *uctx);

typedef int (*fr_machine_signal_t)(fr_machine_t *m, int sig, void *uctx);

typedef void (*fr_machine_hook_func_t)(fr_machine_t *m, int, int, void *uctx);

struct fr_machine_state_s {
	char const		*name;			//!< state name
	int			number;			//!< enum for this state machine
	fr_machine_func_t	enter;			//!< run this when entering the state
	fr_machine_process_t	process;		//!< run this to process the current state
	fr_machine_func_t	exit;			//!< run this when exiting the state
	fr_machine_signal_t	signal;			//!< to send async signals to the state machine
	bool			*allowed;		//!< allow outbound transitions
};

#define ALLOW(_x) .allowed[_x] = true

typedef struct {
	int			max_state;		//!< 1..max states are permitted
	int			max_signal;		//!< 1..max signals are permitted
	int			init;			//!< state to run on init
	int			free;			//!< state to run on free
	fr_machine_state_t	state[];		//!< states
} fr_machine_def_t;

fr_machine_t *fr_machine_alloc(TALLOC_CTX *ctx, fr_machine_def_t const *def, void *uctx);

int fr_machine_process(fr_machine_t *m);

int fr_machine_transition(fr_machine_t *m, int state);

int fr_machine_signal(fr_machine_t *m, int signal);

void fr_machine_pause(fr_machine_t *m);

void fr_machine_resume(fr_machine_t *m);

int fr_machine_current(fr_machine_t *m);

char const *fr_machine_state_name(fr_machine_t *m, int state);

typedef enum {
	FR_MACHINE_ENTER,
	FR_MACHINE_PROCESS,
	FR_MACHINE_EXIT,
	FR_MACHINE_SIGNAL,
} fr_machine_hook_type_t;

typedef enum {
	FR_MACHINE_PRE = 0,
	FR_MACHINE_POST,
} fr_machine_hook_sense_t;

void *fr_machine_hook(fr_machine_t *m, TALLOC_CTX *ctx, int state, fr_machine_hook_type_t type, fr_machine_hook_sense_t sense,
		      bool oneshot, fr_machine_hook_func_t func, void *uctx);

#define MACHINE radius

#define ENTER(_x) static int MACHINE ## _enter ## _x(fr_machine_t *m, void *uctx)
#define EXIT(_x) static int MACHINE ## _exit ## _x(fr_machine_t *m, void *uctx)
#define PROCESS(_x) static int MACHINE ## _process ## _x(fr_machine_t *m, void *uctx)

